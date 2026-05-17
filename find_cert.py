#!/usr/bin/env python3
"""
Finds mitmproxy CA cert and tells you exactly how to install it.
Supports Windows (certutil), macOS (security), and Linux (update-ca-certificates).

Run this once: python find_cert.py
"""

__version__ = "2.0.0"

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

# mitmproxy stores certs here
cert_dir = Path.home() / ".mitmproxy"
cert_cer = cert_dir / "mitmproxy-ca-cert.cer"
cert_pem = cert_dir / "mitmproxy-ca-cert.pem"
cert_p12 = cert_dir / "mitmproxy-ca.p12"

OS = platform.system()   # 'Windows' | 'Darwin' | 'Linux'


def _run(cmd: list, timeout: int = 10) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def install_windows():
    print(f"\n{'='*60}")
    print("  Run this command AS ADMINISTRATOR to install:\n")
    print(f'  certutil -addstore root "{cert_cer}"')
    print(f"\n  Or double-click this file and follow the wizard:")
    print(f"  {cert_cer}")
    print("="*60)

    print("\n[?] Attempt auto-install now? (requires admin) [y/N]: ", end="")
    ans = input().strip().lower()
    if ans == "y":
        result = _run(["certutil", "-addstore", "root", str(cert_cer)])
        if result.returncode == 0:
            print("✅ Certificate installed successfully!")
            print("   Restart your browser and try again.")
        else:
            print("❌ Failed (not running as admin?)")
            print(result.stderr)
            print("\nTry: right-click cmd → 'Run as administrator', then run:")
            print(f'  certutil -addstore root "{cert_cer}"')


def install_macos():
    print(f"\n{'='*60}")
    print("  macOS — Run this in Terminal to install:\n")
    print(f'  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "{cert_pem}"')
    print("="*60)

    print("\n[?] Attempt auto-install now? (requires sudo) [y/N]: ", end="")
    ans = input().strip().lower()
    if ans == "y":
        result = _run([
            "sudo", "security", "add-trusted-cert",
            "-d", "-r", "trustRoot",
            "-k", "/Library/Keychains/System.keychain",
            str(cert_pem),
        ])
        if result.returncode == 0:
            print("✅ Certificate installed successfully!")
            print("   Restart your browser and try again.")
        else:
            print("❌ Failed.")
            print(result.stderr)


def install_linux():
    print(f"\n{'='*60}")
    print("  Linux — copy cert and update the CA store:\n")
    print(f"  sudo cp \"{cert_pem}\" /usr/local/share/ca-certificates/mitmproxy.crt")
    print("  sudo update-ca-certificates")
    print("="*60)

    print("\n[?] Attempt auto-install now? (requires sudo) [y/N]: ", end="")
    ans = input().strip().lower()
    if ans == "y":
        dest = Path("/usr/local/share/ca-certificates/mitmproxy.crt")
        r1 = _run(["sudo", "cp", str(cert_pem), str(dest)])
        if r1.returncode != 0:
            print("❌ Failed to copy cert.")
            print(r1.stderr)
            return
        r2 = _run(["sudo", "update-ca-certificates"])
        if r2.returncode == 0:
            print("✅ Certificate installed successfully!")
            print("   Restart your browser and try again.")
        else:
            print("❌ update-ca-certificates failed.")
            print(r2.stderr)


def main():
    parser = argparse.ArgumentParser(description="mitmproxy CA cert installer helper")
    parser.add_argument("--version", "-V", action="version", version=f"%(prog)s {__version__}")
    parser.parse_args()

    print("\n" + "="*60)
    print("  mitmproxy Certificate Finder")
    print(f"  Platform: {OS}")
    print("="*60)

    if not cert_dir.exists():
        print(f"\n[!] ~/.mitmproxy folder does NOT exist yet.")
        print(f"    mitmproxy hasn't generated certs yet.")
        print(f"    Run the proxy once, then run this script again.")
        return

    print(f"\n✅ Cert folder found: {cert_dir}")
    for f in [cert_cer, cert_pem, cert_p12]:
        status = "✅ exists" if f.exists() else "❌ missing"
        print(f"   {status}  {f}")

    # Pick the right cert file and install routine
    if OS == "Windows":
        if cert_cer.exists():
            install_windows()
        else:
            print("\n[!] .cer file missing — run the proxy once first to generate certs.")
    elif OS == "Darwin":
        if cert_pem.exists():
            install_macos()
        else:
            print("\n[!] .pem file missing — run the proxy once first to generate certs.")
    elif OS == "Linux":
        if cert_pem.exists():
            install_linux()
        else:
            print("\n[!] .pem file missing — run the proxy once first to generate certs.")
    else:
        print(f"\n[!] Unsupported platform: {OS}")
        print(f"    Manually trust: {cert_pem}")


if __name__ == "__main__":
    main()
