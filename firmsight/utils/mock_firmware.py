"""
Mock Vulnerable Firmware Generator
Generates realistic embedded Linux rootfs packages and binary firmware images for testing and triage.
"""

import io
import os
import struct
import tarfile
import tempfile
from pathlib import Path
from typing import Optional

def generate_mock_arm_elf() -> bytes:
    """Generates a valid 52-byte ELF header for 32-bit ARM Little-Endian."""
    # e_ident: \x7fELF, 32-bit (1), little-endian (1), version (1), System V (0), padding
    e_ident = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8
    e_type = 2        # ET_EXEC
    e_machine = 0x28  # EM_ARM
    e_version = 1
    e_entry = 0x00010400
    e_phoff = 52
    e_shoff = 0
    e_flags = 0x05000000  # ARM EABI5
    e_ehsize = 52
    e_phentsize = 32
    e_phnum = 1
    e_shentsize = 40
    e_shnum = 0
    e_shstrndx = 0

    header = e_ident + struct.pack(
        "<HHIIIIIHHHHHH",
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
        e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
    )
    # Append a dummy program header and minimal payload
    dummy_payload = b"\x00" * 128
    return header + dummy_payload

def create_mock_firmware(output_path: Path, arch: str = "ARM") -> Path:
    """Creates a mock firmware binary containing an embedded Linux rootfs."""
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    arm_elf = generate_mock_arm_elf()

    # Build the rootfs in memory as a tarball
    tar_stream = io.BytesIO()
    with tarfile.open(fileobj=tar_stream, mode="w:gz") as tar:
        # 1. /bin/busybox (ARM ELF)
        ti_busybox = tarfile.TarInfo(name="bin/busybox")
        ti_busybox.size = len(arm_elf)
        ti_busybox.mode = 0o755
        tar.addfile(ti_busybox, io.BytesIO(arm_elf))

        # 2. /usr/sbin/uhttpd (ARM ELF)
        ti_httpd = tarfile.TarInfo(name="usr/sbin/uhttpd")
        ti_httpd.size = len(arm_elf)
        ti_httpd.mode = 0o755
        tar.addfile(ti_httpd, io.BytesIO(arm_elf))

        # 3. /etc/passwd (Backdoored account)
        passwd_content = (
            "root:$1$firmsight$abcdefg12345:0:0:root:/root:/bin/sh\n"
            "admin::0:0:admin:/root:/bin/sh\n"
            "nobody:*:65534:65534:nobody:/var:/bin/false\n"
        ).encode("utf-8")
        ti_passwd = tarfile.TarInfo(name="etc/passwd")
        ti_passwd.size = len(passwd_content)
        ti_passwd.mode = 0o644
        tar.addfile(ti_passwd, io.BytesIO(passwd_content))

        # 4. /etc/shadow
        shadow_content = (
            "root:$1$firmsight$abcdefg12345:19000:0:99999:7:::\n"
            "admin::19000:0:99999:7:::\n"
        ).encode("utf-8")
        ti_shadow = tarfile.TarInfo(name="etc/shadow")
        ti_shadow.size = len(shadow_content)
        ti_shadow.mode = 0o600
        tar.addfile(ti_shadow, io.BytesIO(shadow_content))

        # 5. /www/index.html (Router web interface)
        web_content = b"<html><head><title>FirmSight Test Router Admin</title></head><body><h1>Login</h1></body></html>"
        ti_web = tarfile.TarInfo(name="www/index.html")
        ti_web.size = len(web_content)
        ti_web.mode = 0o644
        tar.addfile(ti_web, io.BytesIO(web_content))

    tar_bytes = tar_stream.getvalue()

    # Prepend dummy U-Boot header + firmware signature header
    u_boot_header = b"\x27\x05\x19\x56" + b"FirmSight-Router-v1.0" + (b"\x00" * 40)
    firmware_binary = u_boot_header + tar_bytes

    output_path.write_bytes(firmware_binary)
    return output_path
