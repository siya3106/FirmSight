"""
Unit tests for StaticScanner
"""

import tempfile
from pathlib import Path
from firmsight.analysis.static_scanner import StaticScanner

def test_static_scanner_detections():
    with tempfile.TemporaryDirectory() as tmpdir:
        rootfs = Path(tmpdir)

        # 1. Create a mock private key
        ssl_dir = rootfs / "etc" / "ssl"
        ssl_dir.mkdir(parents=True)
        (ssl_dir / "server.key").write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQ...\n-----END RSA PRIVATE KEY-----")

        # 2. Create a script with hardcoded password and backdoor
        bin_dir = rootfs / "bin"
        bin_dir.mkdir(parents=True)
        (bin_dir / "startup.sh").write_text("#!/bin/sh\npassword='supersecretpass123'\ntelnetd -l /bin/sh -p 2323 &\n")

        scanner = StaticScanner(rootfs)
        results = scanner.scan()

        findings = results["findings"]
        assert len(findings) >= 3

        categories = [f["category"] for f in findings]
        assert "Cryptographic Key / Certificate" in categories
        assert "Backdoor / Credential Leak" in categories

        assert results["summary"]["total"] >= 3
