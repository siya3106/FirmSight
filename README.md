# FirmSight: Automated IoT Firmware Dynamic Analysis Platform 🛡️

**FirmSight** is a terminal-native dynamic analysis and emulation pipeline for embedded Linux IoT firmware (routers, IP cameras, IoT gateways, smart locks). It enables security researchers and defenders to unpack raw firmware binaries, extract foreign filesystems, emulate foreign CPU architectures (ARM/MIPS) via QEMU, trap network traffic in an isolated virtual bridge, trace runtime memory hooks, and monitor botnet/C2 activity in real time through an interactive Terminal UI (TUI).

---

## 🌟 Key Features

- **Automated Extraction Engine**: Seamlessly uncarves root filesystems (SquashFS, CramFS, JFFS2, tarballs) using Binwalk and signature-fallback extractors.
- **Cross-Architecture Detection**: Direct ELF header parser identifying CPU architectures (ARM, AArch64, MIPS-EB, MIPS-EL, x86, RISC-V) and matching appropriate QEMU static emulators.
- **QEMU Emulation Supervisor**: Supports user-mode `chroot` emulation (`qemu-arm-static`, `qemu-mipseb-static`) and full-system virtualization harnesses.
- **Network Isolation & Telemetry**: Sandboxes emulated instances into isolated virtual network namespaces (`tap0` / bridge) with integrated PCAP flow logging.
- **Behavioral & C2 Heuristics**: Analyzes DNS lookups, outbound socket attempts, and potential botnet signatures (e.g. Mirai/Gafgyt sweeps) in real time.
- **Dynamic Memory Tracing**: Connects to running processes via `r2pipe` / Radare2 to audit memory maps and execution states.
- **Interactive Terminal UI (TUI)**: Powered by Textual with multi-pane navigation for Filesystem inspection, Emulation logs, and Network telemetry.

---

## 📁 Repository Structure

```text
firmsight/
├── pyproject.toml
├── requirements.txt
├── README.md
├── firmsight/
│   ├── __init__.py
│   ├── cli.py                     # Main CLI command dispatcher
│   ├── core/
│   │   ├── __init__.py
│   │   ├── detector.py            # Architecture & ELF parser
│   │   ├── extractor.py           # Binwalk & archive extraction engine
│   │   ├── emulator.py            # QEMU environment supervisor
│   │   ├── network.py             # TUN/TAP network isolation
│   │   └── tracer.py              # r2pipe / GDB dynamic memory tracer
│   ├── analysis/
│   │   ├── __init__.py
│   │   ├── pcap_analyzer.py       # Live packet streaming
│   │   └── heuristics.py          # Behavioral anomaly & C2 heuristic engine
│   ├── ui/
│   │   ├── __init__.py
│   │   ├── app.py                 # Textual application main class
│   │   ├── styles.tcss            # UI styling and responsive layout
│   │   └── widgets/
│   │       ├── fs_tree.py         # Filesystem explorer pane
│   │       ├── log_viewer.py      # Live emulation stdout/stderr stream
│   │       ├── net_table.py       # Live network connections table
│   │       └── mem_viewer.py      # Memory maps & tracing pane
│   └── utils/
│       ├── __init__.py
│       ├── logger.py              # Centralized logging
│       └── mock_firmware.py       # Vulnerable mock router firmware generator
├── scripts/
│   ├── setup_net.sh               # Linux TAP bridge setup
│   └── teardown_net.sh            # Safe cleanup script
└── tests/
    ├── test_detector.py
    ├── test_extractor.py
    └── test_heuristics.py
```

---

## 🚀 Quickstart Guide

### 1. Installation
Clone the repository and install the dependencies:
```bash
git clone https://github.com/siya3106/FirmSight.git
cd FirmSight
pip install -r requirements.txt
pip install -e .
```

### 2. Generate a Mock Vulnerable Firmware (for testing)
If you don't have a physical firmware binary on hand, generate a mock ARM-based vulnerable router firmware image:
```bash
firmsight make-mock --output router_firmware.bin
```

### 3. Extract Filesystem
```bash
firmsight extract router_firmware.bin --output extracted_rootfs/
```

### 4. Detect Architecture
```bash
firmsight detect extracted_rootfs/
```

### 5. Launch the Interactive Terminal UI (TUI)
```bash
firmsight tui --firmware router_firmware.bin
# Or open directly on an already-extracted rootfs:
firmsight tui --rootfs extracted_rootfs/
```

---

## 🛡️ Defensive & Research Ethics
FirmSight is strictly an auditing, reverse-engineering, and dynamic analysis sandbox built for security researchers, embedded engineers, and defenders to analyze firmware behavior in isolated sandbox environments.
