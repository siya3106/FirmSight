"""
Unit tests for SecurityReporter
"""

import json
import tempfile
from pathlib import Path
from firmsight.analysis.reporter import SecurityReporter

def test_reporter_markdown_and_json():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        reporter = SecurityReporter(target_name="TestFirmware")

        reporter.set_arch_results({
            "arch": "ARM",
            "bitness": 32,
            "endianness": "little",
            "qemu_target": "qemu-arm-static",
        })
        reporter.set_extraction_results({
            "file_count": 42,
            "total_bytes": 10240,
            "method": "tar_archive",
            "sensitive_files": [
                {"path": "etc/passwd", "description": "Empty password check", "size_bytes": 120}
            ],
        })
        reporter.add_network_event({
            "source": "192.168.1.50",
            "destination": "198.51.100.42:4444",
            "protocol": "TCP",
            "severity": "HIGH",
            "info": "C2 beacon",
            "flagged": True,
        })

        md_file = tmp_path / "report.md"
        json_file = tmp_path / "report.json"

        md_content = reporter.generate_markdown(md_file)
        json_content = reporter.generate_json(json_file)

        assert md_file.is_file()
        assert "TestFirmware" in md_content
        assert "etc/passwd" in md_content

        assert json_file.is_file()
        parsed = json.loads(json_content)
        assert parsed["target"] == "TestFirmware"
        assert parsed["architecture"]["arch"] == "ARM"
        assert len(parsed["findings"]["network_anomalies"]) == 1
