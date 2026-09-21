"""
Unit tests for Traffic Heuristics and C2 Detection
"""

from firmsight.analysis.heuristics import TrafficHeuristicsEngine

def test_flagged_port_event():
    event = {
        "src": "192.168.1.50",
        "dst": "198.51.100.42:4444",
        "proto": "TCP",
        "info": "Connection attempt to 4444",
    }
    res = TrafficHeuristicsEngine.evaluate_event(event)
    assert res["flagged"] is True
    assert res["severity"] == "HIGH"
    assert any("port 4444" in r for r in res["reasons"])

def test_normal_event():
    event = {
        "src": "192.168.1.50",
        "dst": "192.168.1.1:53",
        "proto": "DNS",
        "info": "Standard query for pool.ntp.org",
    }
    res = TrafficHeuristicsEngine.evaluate_event(event)
    assert res["flagged"] is False
    assert res["severity"] == "NORMAL"

def test_mirai_sweep_event():
    event = {
        "src": "192.168.1.50",
        "dst": "203.0.113.10:23",
        "proto": "TELNET",
        "info": "Telnet SYN sweep scanning detected",
    }
    res = TrafficHeuristicsEngine.evaluate_event(event)
    assert res["flagged"] is True
    assert res["severity"] == "CRITICAL"
