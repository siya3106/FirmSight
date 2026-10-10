"""
DNS Sinkhole and Query Logger
Listens on virtual interface UDP port 53, captures DNS requests, logs queries,
and returns synthetic responses to keep isolated firmware daemons alive without real internet access.
"""

import socket
import struct
import threading
from typing import Dict, Any, List, Optional, Callable

class DNSSinkhole:
    """Mock DNS server providing query logging and synthetic IP resolution for sandbox networks."""

    def __init__(
        self,
        listen_ip: str = "127.0.0.1",
        listen_port: int = 5353, # Default 5353 so unprivileged users can test without root
        sinkhole_ip: str = "192.168.1.1",
        on_query: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.sinkhole_ip = sinkhole_ip
        self.on_query = on_query

        self.queries_log: List[Dict[str, Any]] = []
        self._is_running = False
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        """Starts DNS listener thread."""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.bind((self.listen_ip, self.listen_port))
            self._is_running = True
            self._thread = threading.Thread(target=self._listen_loop, daemon=True)
            self._thread.start()
            return True
        except Exception:
            return False

    def _listen_loop(self):
        """Processes incoming UDP DNS requests."""
        while self._is_running and self._sock:
            try:
                data, addr = self._sock.recvfrom(512)
                if len(data) < 12:
                    continue

                domain = self._parse_dns_query(data[12:])
                is_suspicious = any(tld in domain for tld in [".xyz", ".tk", ".top", ".duckdns.org", "botnet"])

                event = {
                    "client_ip": addr[0],
                    "domain": domain,
                    "resolved_ip": self.sinkhole_ip,
                    "suspicious": is_suspicious,
                }
                self.queries_log.append(event)
                if self.on_query:
                    self.on_query(event)

                # Craft synthetic response
                response = self._build_dns_response(data, self.sinkhole_ip)
                self._sock.sendto(response, addr)
            except Exception:
                break

    @staticmethod
    def _parse_dns_query(query_bytes: bytes) -> str:
        """Extracts queried domain name from DNS question section."""
        parts = []
        idx = 0
        while idx < len(query_bytes):
            length = query_bytes[idx]
            if length == 0:
                break
            idx += 1
            parts.append(query_bytes[idx : idx + length].decode("ascii", errors="ignore"))
            idx += length
        return ".".join(parts)

    @staticmethod
    def _build_dns_response(request_data: bytes, resolved_ip: str) -> bytes:
        """Constructs a basic standard A-record response."""
        # Copy transaction ID and set response flags (0x8180 = standard response, no error)
        trans_id = request_data[:2]
        flags = b"\x81\x80"
        qd_count = request_data[4:6]
        an_count = b"\x00\x01" # 1 Answer
        ns_count = b"\x00\x00"
        ar_count = b"\x00\x00"

        header = trans_id + flags + qd_count + an_count + ns_count + ar_count

        # Find end of question section
        q_end = 12
        while q_end < len(request_data) and request_data[q_end] != 0:
            q_end += request_data[q_end] + 1
        q_end += 5 # Skip null terminator + QTYPE + QCLASS

        question = request_data[12:q_end]

        # Answer: pointer to domain name (0xc00c), Type A (1), Class IN (1), TTL 60s, Len 4, IP bytes
        answer_hdr = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"
        ip_bytes = socket.inet_aton(resolved_ip)

        return header + question + answer_hdr + ip_bytes

    def stop(self):
        """Stops DNS listener."""
        self._is_running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
