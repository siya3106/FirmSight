"""
PCAP Packet Capture Parser and Live Flow Streamer
"""

import struct
from pathlib import Path
from typing import List, Dict, Any, Generator

class PCAPAnalyzer:
    """Parses standard Libpcap (.pcap) files directly in pure Python."""

    PCAP_MAGIC_LITTLE = 0xA1B2C3D4
    PCAP_MAGIC_BIG = 0xD4C3B2A1

    def __init__(self, pcap_path: Path):
        self.pcap_path = Path(pcap_path)

    def parse_packets(self) -> Generator[Dict[str, Any], None, None]:
        """Reads packets from a PCAP file without external dependencies."""
        if not self.pcap_path.is_file():
            return

        with open(self.pcap_path, "rb") as f:
            header = f.read(24)
            if len(header) < 24:
                return

            magic = struct.unpack("<I", header[:4])[0]
            if magic == self.PCAP_MAGIC_LITTLE:
                endian = "<"
            elif magic == self.PCAP_MAGIC_BIG:
                endian = ">"
            else:
                return  # Unsupported / invalid PCAP magic

            while True:
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkt_hdr)
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                # Quick Ethernet + IP framing parse
                if len(pkt_data) >= 34:
                    eth_type = struct.unpack("!H", pkt_data[12:14])[0]
                    if eth_type == 0x0800:  # IPv4
                        ip_hdr = pkt_data[14:34]
                        proto = ip_hdr[9]
                        src_ip = ".".join(map(str, ip_hdr[12:16]))
                        dst_ip = ".".join(map(str, ip_hdr[16:20]))
                        proto_name = "TCP" if proto == 6 else ("UDP" if proto == 17 else f"IP-{proto}")

                        yield {
                            "timestamp": f"{ts_sec}.{ts_usec}",
                            "src": src_ip,
                            "dst": dst_ip,
                            "proto": proto_name,
                            "length": incl_len,
                        }
