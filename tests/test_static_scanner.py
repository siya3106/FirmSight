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

def test_token_entropy_calculation():
    # Repetitive token has low entropy
    low_ent = StaticScanner.calculate_string_entropy("aaaaaaaaaaaaaaaaaaaa")
    assert low_ent == 0.0

    # High-entropy random token
    high_ent = StaticScanner.calculate_string_entropy("9F8a7B2c1D4e6F0g_aZ+9L==")
    assert high_ent > 3.8

def test_high_entropy_token_scanning():
    with tempfile.TemporaryDirectory() as tmpdir:
        rootfs = Path(tmpdir)
        cfg_dir = rootfs / "etc"
        cfg_dir.mkdir(parents=True)

        # File containing high-entropy API key
        (cfg_dir / "cloud.conf").write_text(
            'api_token="9F8a7B2c1D4e6F0gZaZ9LxKyWmQp"\n'
            'device_user="admin"\n'
        )

        scanner = StaticScanner(rootfs)
        results = scanner.scan()
        findings = results["findings"]

        categories = [f["category"] for f in findings]
        assert "High-Entropy Secret / API Token" in categories
        assert "Factory Default Credential" in categories
