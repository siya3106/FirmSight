"""
Shannon Entropy Calculator and Encryption/Compression Detector
Calculates sliding-window entropy across raw binary blobs to identify
compressed sections (SquashFS, LZMA) and encrypted blocks.
"""

import math
from collections import Counter
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

class EntropyAnalyzer:
    """Calculates Shannon entropy to differentiate between plain text/code, compressed, and encrypted data."""

    # Standard entropy thresholds (0.0 to 8.0 bits per byte)
    THRESHOLD_PLAIN = 5.0        # Plaintext, uncompressed code, sparse padding
    THRESHOLD_COMPRESSED = 7.2   # Typical of Gzip, SquashFS, LZMA
    THRESHOLD_ENCRYPTED = 7.9    # Uniformly random distribution typical of AES, ChaCha20, or raw crypto

    def __init__(self, block_size: int = 1024, step_size: int = 512):
        self.block_size = block_size
        self.step_size = step_size

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculates the Shannon entropy of a byte buffer (0.0 to 8.0)."""
        if not data:
            return 0.0

        length = len(data)
        counts = Counter(data)
        entropy = 0.0

        for count in counts.values():
            prob = count / length
            entropy -= prob * math.log2(prob)

        return round(entropy, 4)

    def analyze_file(self, filepath: Path) -> Dict[str, Any]:
        """Performs sliding-window entropy analysis across a binary file."""
        path = Path(filepath).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")

        data = path.read_bytes()
        return self.analyze_bytes(data, filename=path.name)

    def analyze_bytes(self, data: bytes, filename: str = "binary_data") -> Dict[str, Any]:
        """Calculates sliding-window entropy curve and identifies suspicious high-entropy blocks."""
        total_len = len(data)
        overall_entropy = self.calculate_entropy(data)

        curve: List[Dict[str, Any]] = []
        suspicious_blocks: List[Dict[str, Any]] = []

        offset = 0
        while offset < total_len:
            chunk = data[offset : offset + self.block_size]
            if not chunk:
                break

            chunk_ent = self.calculate_entropy(chunk)
            block_type = self._classify_entropy(chunk_ent)

            record = {
                "offset": offset,
                "hex_offset": f"0x{offset:08X}",
                "length": len(chunk),
                "entropy": chunk_ent,
                "classification": block_type,
            }
            curve.append(record)

            if block_type in ("COMPRESSED", "ENCRYPTED"):
                suspicious_blocks.append(record)

            offset += self.step_size

        # Aggregate detected contiguous regions
        regions = self._aggregate_regions(curve)

        return {
            "target": filename,
            "total_bytes": total_len,
            "overall_entropy": overall_entropy,
            "overall_classification": self._classify_entropy(overall_entropy),
            "curve_samples": len(curve),
            "regions": regions,
        }

    def _classify_entropy(self, entropy: float) -> str:
        """Classifies an entropy score."""
        if entropy < self.THRESHOLD_PLAIN:
            return "LOW_ENTROPY"      # Plaintext, sparse zeros, ELF headers
        elif entropy < self.THRESHOLD_COMPRESSED:
            return "MODERATE_ENTROPY" # Executable machine code, structured resources
        elif entropy < self.THRESHOLD_ENCRYPTED:
            return "COMPRESSED"       # Compressed filesystem or payload (SquashFS/Gzip)
        else:
            return "ENCRYPTED"        # High-entropy uniform distribution (encrypted or packed)

    def _aggregate_regions(self, curve: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Combines adjacent sliding-window samples into continuous contiguous regions."""
        if not curve:
            return []

        regions = []
        cur_type = curve[0]["classification"]
        start_offset = curve[0]["offset"]
        end_offset = start_offset + curve[0]["length"]
        total_ent = curve[0]["entropy"]
        count = 1

        for sample in curve[1:]:
            sample_type = sample["classification"]
            if sample_type == cur_type:
                end_offset = sample["offset"] + sample["length"]
                total_ent += sample["entropy"]
                count += 1
            else:
                regions.append({
                    "start_offset": f"0x{start_offset:08X}",
                    "end_offset": f"0x{end_offset:08X}",
                    "length": end_offset - start_offset,
                    "classification": cur_type,
                    "avg_entropy": round(total_ent / count, 4),
                })
                cur_type = sample_type
                start_offset = sample["offset"]
                end_offset = start_offset + sample["length"]
                total_ent = sample["entropy"]
                count = 1

        regions.append({
            "start_offset": f"0x{start_offset:08X}",
            "end_offset": f"0x{end_offset:08X}",
            "length": end_offset - start_offset,
            "classification": cur_type,
            "avg_entropy": round(total_ent / count, 4),
        })

        return regions
