"""
Unit tests for HTMLReporter
"""

import tempfile
from pathlib import Path
from firmsight.analysis.html_reporter import HTMLReporter

def test_html_rendering():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_html = Path(tmpdir) / "report.html"
        dummy_data = {
            "target": "RouterFirmware-v1.bin",
            "architecture": {"arch": "ARM", "bitness": 32, "endianness": "little"},
            "extraction_stats": {"file_count": 150, "method": "binwalk"},
            "findings": {
                "sensitive_files": [{"path": "etc/passwd", "description": "Backdoor account", "size_bytes": 100}],
                "network_anomalies": [{"severity": "CRITICAL", "source": "192.168.1.10", "destination": "198.51.100.42:4444", "protocol": "TCP", "info": "C2 Beacon"}],
                "static_vulnerabilities": [{"severity": "HIGH", "cwe": "CWE-798", "path": "etc/config", "description": "Hardcoded key"}],
                "crashes": [],
            },
        }

        html = HTMLReporter.render(dummy_data, output_path=out_html)
        assert out_html.is_file()
        assert "<!DOCTYPE html>" in html
        assert "RouterFirmware-v1.bin" in html
        assert "C2 Beacon" in html
        assert "CWE-798" in html
