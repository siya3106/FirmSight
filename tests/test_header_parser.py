"""
Unit tests for HeaderParser (uImage and TRX)
"""

import struct
import tempfile
from pathlib import Path
from firmsight.core.header_parser import HeaderParser

def test_uimage_header_parsing():
    with tempfile.TemporaryDirectory() as tmpdir:
        fw_path = Path(tmpdir) / "test_uimage.bin"

        # Construct a synthetic 64-byte U-Boot header
        # magic (0x27051956), hcrc (0x12345678), time (1700000000), size (4096),
        # load (0x80000000), ep (0x80000000), dcrc (0xabcdef12), os (Linux=5),
        # arch (ARM=2), type (Kernel=2), comp (Gzip=1)
        magic = 0x27051956
        hcrc = 0x12345678
        epoch = 1700000000
        size = 4096
        load_addr = 0x80000000
        ep = 0x80000000
        dcrc = 0xabcdef12
        os_type = 5
        arch = 2       # ARM
        img_type = 2   # OS Kernel
        comp = 1       # Gzip
        name = b"FirmSight-ARM-Linux\x00" + b"\x00" * 12

        hdr = struct.pack(">IIIIIIIBBBB", magic, hcrc, epoch, size, load_addr, ep, dcrc, os_type, arch, img_type, comp) + name
        padding = b"\x00" * 256
        fw_path.write_bytes(padding + hdr + (b"\xff" * 512))

        headers = HeaderParser.parse_file(fw_path)
        assert len(headers) == 1

        uimg = headers[0]
        assert uimg["format"] == "U-Boot uImage"
        assert uimg["offset"] == 256
        assert uimg["arch"] == "ARM"
        assert uimg["image_name"] == "FirmSight-ARM-Linux"
        assert uimg["compression"] == "Gzip"
        assert uimg["load_address"] == "0x80000000"

def test_trx_header_parsing():
    with tempfile.TemporaryDirectory() as tmpdir:
        fw_path = Path(tmpdir) / "test_broadcom.trx"

        # Construct Broadcom TRX header:
        # magic ('HDR0'), total_len (65536), crc32 (0x11223344), flags_version (v1=0x00010000),
        # offset0 (28), offset1 (4096), offset2 (0)
        magic = b"HDR0"
        total_len = 65536
        crc32 = 0x11223344
        flags_version = 0x00010000  # version 1, flags 0
        offset0 = 28
        offset1 = 4096
        offset2 = 0

        hdr = struct.pack("<4sIIIIII", magic, total_len, crc32, flags_version, offset0, offset1, offset2)
        fw_path.write_bytes(hdr + (b"\x00" * 256))

        headers = HeaderParser.parse_file(fw_path)
        assert len(headers) == 1

        trx = headers[0]
        assert trx["format"] == "Broadcom TRX"
        assert trx["version"] == 1
        assert trx["total_size"] == 65536
        assert len(trx["partition_offsets"]) == 3
