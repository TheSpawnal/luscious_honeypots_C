#!/usr/bin/env python3
"""
triage - static first-pass analysis for captured honeypot artifacts.

It NEVER executes the sample. It computes identity hashes, detects file
type, measures entropy, extracts strings and indicators of compromise, and
parses executable headers (ELF/PE) to orient you before deeper reversing.

Dynamic analysis (running the sample) must happen only inside an isolated,
network-segmented lab. This tool is the safe first step before that.

Core features use the standard library only. Optional, auto-detected:
  pyelftools  -> ELF sections/imports     (pip install pyelftools)
  pefile      -> PE  sections/imports      (pip install pefile)
  capstone    -> entry-point disassembly   (pip install capstone)
"""

import argparse
import hashlib
import json
import math
import os
import re
import struct
import sys

# ---- optional dependencies (degrade gracefully) -------------------------
try:
    from elftools.elf.elffile import ELFFile
    HAVE_ELFTOOLS = True
except Exception:
    HAVE_ELFTOOLS = False

try:
    import pefile
    HAVE_PEFILE = True
except Exception:
    HAVE_PEFILE = False

try:
    import capstone
    HAVE_CAPSTONE = True
except Exception:
    HAVE_CAPSTONE = False


# ---- hashing & entropy --------------------------------------------------
def hashes(data):
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def shannon_entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent  # bits per byte, 0..8


# ---- file typing --------------------------------------------------------
MAGIC = [
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "PE/DOS executable"),
    (b"\xca\xfe\xba\xbe", "Mach-O fat binary"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit"),
    (b"PK\x03\x04", "ZIP/JAR/APK archive"),
    (b"\x1f\x8b", "gzip stream"),
    (b"BZh", "bzip2 stream"),
    (b"\xfd7zXZ\x00", "xz stream"),
    (b"ustar", "tar archive"),
    (b"\x89PNG", "PNG image"),
    (b"#!", "script (shebang)"),
    (b"<?php", "PHP script"),
]


def file_type(data):
    for sig, name in MAGIC:
        if data.startswith(sig):
            return name
    # shebang may follow whitespace; check first line
    head = data[:64]
    if head[:2] == b"#!" or head.lstrip().startswith(b"#!"):
        first = data.split(b"\n", 1)[0][:80]
        return "script: " + first.decode("latin-1", "replace")
    if all(32 <= b < 127 or b in (9, 10, 13) for b in data[:512] or b""):
        return "ASCII/text"
    return "unknown/raw"


# ---- strings ------------------------------------------------------------
def ascii_strings(data, minlen=4):
    out, cur = [], bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("ascii"))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode("ascii"))
    return out


def utf16le_strings(data, minlen=4):
    out, cur = [], bytearray()
    i = 0
    while i + 1 < len(data):
        lo, hi = data[i], data[i + 1]
        if 32 <= lo < 127 and hi == 0:
            cur.append(lo)
            i += 2
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("ascii"))
            cur = bytearray()
            i += 1
    if len(cur) >= minlen:
        out.append(cur.decode("ascii"))
    return out


# ---- indicators of compromise ------------------------------------------
RE_URL = re.compile(r"\b(?:https?|ftp|tftp)://[^\s\"'<>|;`]{4,}")
RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
RE_ONION = re.compile(r"\b[a-z2-7]{16,56}\.onion\b")
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RE_PATH = re.compile(r"(?:/(?:bin|etc|tmp|var|usr|dev|proc|root|home)/[^\s\"'`]*)")

SUSPECT_TOKENS = [
    "wget", "curl", "tftp", "busybox", "/bin/sh", "/bin/bash", "chmod +x",
    "nc ", "ncat", "netcat", "reverse", "bind", "LD_PRELOAD", "ptrace",
    "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "WSAStartup",
    "RegSetValue", "schtasks", "powershell", "cmd.exe", "/etc/passwd",
    "/etc/shadow", "crontab", "iptables", "rm -rf", "kill -9", "mirai",
    "gafgyt", "xmrig", "monero", "stratum+tcp", "0.0.0.0",
]


def extract_iocs(strings):
    blob = "\n".join(strings)
    iocs = {
        "urls": sorted(set(RE_URL.findall(blob))),
        "onion": sorted(set(RE_ONION.findall(blob))),
        "ipv4": sorted({ip for ip in RE_IPV4.findall(blob)
                        if all(0 <= int(o) <= 255 for o in ip.split("."))}),
        "emails": sorted(set(RE_EMAIL.findall(blob))),
        "paths": sorted(set(RE_PATH.findall(blob)))[:50],
    }
    # domains minus bare IPs
    domains = {d for d in RE_DOMAIN.findall(blob)
               if not RE_IPV4.fullmatch(d)}
    iocs["domains"] = sorted(domains)[:50]
    low = blob.lower()
    iocs["suspect_tokens"] = sorted({t for t in SUSPECT_TOKENS
                                     if t.lower() in low})
    return iocs


# ---- ELF (manual header, optional deep) --------------------------------
ELF_MACHINE = {0x03: "x86", 0x3e: "x86-64", 0x28: "ARM", 0xb7: "AArch64",
               0x08: "MIPS", 0x14: "PowerPC", 0xf3: "RISC-V"}
ELF_TYPE = {1: "REL", 2: "EXEC", 3: "DYN/PIE", 4: "CORE"}


def parse_elf_header(data):
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return None
    cls = "64-bit" if data[4] == 2 else "32-bit"
    endian = "little" if data[5] == 1 else "big"
    e = "<" if data[5] == 1 else ">"
    etype = struct.unpack_from(e + "H", data, 16)[0]
    machine = struct.unpack_from(e + "H", data, 18)[0]
    info = {
        "class": cls,
        "endian": endian,
        "type": ELF_TYPE.get(etype, str(etype)),
        "machine": ELF_MACHINE.get(machine, hex(machine)),
        "stripped": b".debug" not in data,
    }
    if data[4] == 2:
        info["entry"] = hex(struct.unpack_from(e + "Q", data, 24)[0])
    else:
        info["entry"] = hex(struct.unpack_from(e + "I", data, 24)[0])
    return info


def elf_deep(path):
    if not HAVE_ELFTOOLS:
        return None
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            sections = [s.name for s in elf.iter_sections() if s.name]
            imports = []
            for sec in elf.iter_sections():
                if sec.name in (".dynsym", ".symtab"):
                    for sym in sec.iter_symbols():
                        if sym.name and sym["st_info"]["type"] == "STT_FUNC" \
                           and sym["st_shndx"] == "SHN_UNDEF":
                            imports.append(sym.name)
            return {"sections": sections[:40],
                    "imported_symbols": sorted(set(imports))[:60]}
    except Exception as ex:
        return {"error": str(ex)}


# ---- PE (optional) ------------------------------------------------------
def pe_info(path, data):
    if data[:2] != b"MZ":
        return None
    if not HAVE_PEFILE:
        return {"note": "install pefile for PE section/import detail"}
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        info = {
            "machine": hex(pe.FILE_HEADER.Machine),
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "sections": [s.Name.rstrip(b"\x00").decode("latin-1", "replace")
                         for s in pe.sections],
            "dlls": [],
        }
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            info["dlls"].append(entry.dll.decode("latin-1", "replace"))
        return info
    except Exception as ex:
        return {"error": str(ex)}


# ---- entry disassembly (optional) --------------------------------------
def disasm_elf_entry(data, elf_hdr, count=20):
    if not HAVE_CAPSTONE or not elf_hdr:
        return None
    arch_map = {
        "x86-64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
        "AArch64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        "ARM": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
    }
    sel = arch_map.get(elf_hdr["machine"])
    if not sel:
        return None
    # crude: disassemble bytes near the start of the .text-ish region
    try:
        entry = int(elf_hdr["entry"], 16)
        md = capstone.Cs(*sel)
        # without full section mapping we disassemble file offset 0x1000 window
        window = data[0x1000:0x1000 + 64] if len(data) > 0x1000 else data[:64]
        out = []
        for ins in md.disasm(window, entry):
            out.append(f"{ins.address:#x}  {ins.mnemonic} {ins.op_str}".strip())
            if len(out) >= count:
                break
        return out or None
    except Exception:
        return None


# ---- per-file analysis --------------------------------------------------
def analyze(path):
    with open(path, "rb") as f:
        data = f.read()

    ftype = file_type(data)
    a_str = ascii_strings(data)
    w_str = utf16le_strings(data)
    all_str = a_str + w_str
    ent = shannon_entropy(data)

    rep = {
        "path": path,
        "size": len(data),
        "hashes": hashes(data),
        "file_type": ftype,
        "entropy": round(ent, 3),
        "entropy_note": ("high (packed/encrypted/compressed)" if ent >= 7.2
                         else "normal"),
        "string_counts": {"ascii": len(a_str), "utf16le": len(w_str)},
        "iocs": extract_iocs(all_str),
    }

    elf_hdr = parse_elf_header(data)
    if elf_hdr:
        rep["elf"] = elf_hdr
        deep = elf_deep(path)
        if deep:
            rep["elf"].update(deep)
        dis = disasm_elf_entry(data, elf_hdr)
        if dis:
            rep["entry_disasm"] = dis

    pe = pe_info(path, data)
    if pe:
        rep["pe"] = pe

    return rep


# ---- text rendering -----------------------------------------------------
def render_text(rep):
    L = []
    L.append(f"file        {rep['path']}")
    L.append(f"size        {rep['size']} bytes")
    L.append(f"type        {rep['file_type']}")
    L.append(f"entropy     {rep['entropy']} bits/byte ({rep['entropy_note']})")
    h = rep["hashes"]
    L.append(f"md5         {h['md5']}")
    L.append(f"sha1        {h['sha1']}")
    L.append(f"sha256      {h['sha256']}")
    sc = rep["string_counts"]
    L.append(f"strings     ascii={sc['ascii']} utf16le={sc['utf16le']}")

    if "elf" in rep:
        e = rep["elf"]
        L.append("")
        L.append("ELF")
        L.append(f"  class={e['class']} endian={e['endian']} type={e['type']} "
                 f"machine={e['machine']} entry={e['entry']} "
                 f"stripped={e['stripped']}")
        if e.get("sections"):
            L.append(f"  sections    {', '.join(e['sections'])}")
        if e.get("imported_symbols"):
            L.append(f"  imports     {', '.join(e['imported_symbols'][:30])}")
    if "pe" in rep:
        L.append("")
        L.append("PE")
        for k, v in rep["pe"].items():
            L.append(f"  {k:<11} {v}")
    if "entry_disasm" in rep:
        L.append("")
        L.append("entry disassembly")
        for line in rep["entry_disasm"]:
            L.append(f"  {line}")

    ioc = rep["iocs"]
    nonempty = {k: v for k, v in ioc.items() if v}
    if nonempty:
        L.append("")
        L.append("indicators")
        for k, v in nonempty.items():
            L.append(f"  {k:<14} {', '.join(v[:20])}")
    return "\n".join(L)


def iter_targets(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for fn in files:
                    yield os.path.join(root, fn)
        elif os.path.isfile(p):
            yield p
        else:
            sys.stderr.write(f"triage: not found: {p}\n")


def main():
    ap = argparse.ArgumentParser(
        description="Static triage of captured artifacts. Never executes the sample.")
    ap.add_argument("paths", nargs="+", help="file(s) or directory to analyze")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = ap.parse_args()

    caps = []
    if not HAVE_ELFTOOLS:
        caps.append("pyelftools(ELF deep)")
    if not HAVE_PEFILE:
        caps.append("pefile(PE deep)")
    if not HAVE_CAPSTONE:
        caps.append("capstone(disasm)")
    if caps and not args.json:
        sys.stderr.write("optional modules missing: " + ", ".join(caps) + "\n\n")

    reports = []
    for target in iter_targets(args.paths):
        try:
            rep = analyze(target)
        except Exception as ex:
            sys.stderr.write(f"triage: {target}: {ex}\n")
            continue
        reports.append(rep)
        if not args.json:
            print(render_text(rep))
            print("-" * 72)

    if args.json:
        print(json.dumps(reports, indent=2))

    # reminder, not an emoji, kept terse
    if not args.json and reports:
        sys.stderr.write(
            "\nNOTE: dynamic analysis (running the sample) must occur only in "
            "an isolated, network-segmented lab.\n")


if __name__ == "__main__":
    main()
