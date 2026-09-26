"""
Unit tests for EntropyAnalyzer
"""

import os
import zlib
from pathlib import Path
from firmsight.analysis.entropy import EntropyAnalyzer

def test_entropy_zero_bytes():
    assert EntropyAnalyzer.calculate_entropy(b"") == 0.0

def test_entropy_uniform_single_byte():
    # Repeated bytes have 0 entropy
    data = b"\x00" * 2048
    assert EntropyAnalyzer.calculate_entropy(data) == 0.0

def test_entropy_plaintext():
    text = (b"The quick brown fox jumps over the lazy dog. " * 50)
    ent = EntropyAnalyzer.calculate_entropy(text)
    # Natural English text typically has entropy between 3.5 and 4.8
    assert 3.5 <= ent <= 5.0

def test_entropy_compressed():
    raw_payload = os.urandom(4096)
    compressed = zlib.compress(raw_payload)
    ent = EntropyAnalyzer.calculate_entropy(compressed)
    # Compressed data typically yields > 7.2 bits per byte
    assert ent >= 7.2

def test_sliding_window_analysis():
    # Construct a composite buffer: 1024 bytes of zero padding + 2048 bytes of pseudo-random data
    padding = b"\x00" * 1024
    random_bytes = os.urandom(2048)
    composite = padding + random_bytes

    analyzer = EntropyAnalyzer(block_size=512, step_size=256)
    result = analyzer.analyze_bytes(composite, filename="test_composite.bin")

    assert result["total_bytes"] == 3072
    assert result["curve_samples"] > 0
    assert len(result["regions"]) >= 2

    # First region should be LOW_ENTROPY
    assert result["regions"][0]["classification"] == "LOW_ENTROPY"
