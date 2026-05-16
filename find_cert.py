#!/usr/bin/env python3
"""
Finds mitmproxy CA cert and tells you exactly how to install it.
Run this once: python find_cert.py
"""
import os
import subprocess
from pathlib import Path

# mitmproxy stores certs here
cert_dir = Path.home() / ".mitmproxy"
cert_cer = cert_dir / "mitmproxy-ca-cert.cer"
cert_pem = cert_dir / "mitmproxy-ca-cert.pem"
cert_p12 = cert_dir / "mitmproxy-ca.p12"

print("\n" + "="*60)
print("  mitmproxy Certificate Finder")
print("="*60)

if not cert_dir.exists():
    print(f"\n[!] ~/.mitmproxy folder does NOT exist yet.")
    print(f"    mitmproxy hasn't generated certs yet.")
    print(f"    Run the proxy once, then run this script again.")
else:
    print(f"\n✅ Cert folder found: {cert_dir}")
    for f in [cert_cer, cert_pem, cert_p12]:
        status = "✅ exists" if f.exists() else "❌ missing"
        print(f"   {status}  {f}")

    if cert_cer.exists():
        print(f"\n" + "="*60)
        print(f"  Run this command AS ADMINISTRATOR to install:\n")
        print(f'  certutil -addstore root "{cert_cer}"')
        print(f"\n  Or double-click this file and follow the wizard:")
        print(f"  {cert_cer}")
        print("="*60)

        # Try to auto-install
        print("\n[?] Attempt auto-install now? (requires admin) [y/N]: ", end="")
        ans = input().strip().lower()
        if ans == "y":
            result = subprocess.run(
                ["certutil", "-addstore", "root", str(cert_cer)],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                print("✅ Certificate installed successfully!")
                print("   Restart your browser and try again.")
            else:
                print("❌ Failed (not running as admin?)")
                print(result.stderr)
                print("\nTry: right-click cmd → 'Run as administrator', then run:")
                print(f'  certutil -addstore root "{cert_cer}"')
    else:
        print("\n[!] .cer file missing — run the proxy once first to generate certs.")
