#!/usr/bin/env bash
# FirmSight Virtual Network Teardown Script
set -e

TAP_DEV="tap0"
BR_DEV="br0"

echo "[FirmSight] Cleaning up network interfaces..."
ip link set $BR_DEV down 2>/dev/null || true
ip link delete $BR_DEV type bridge 2>/dev/null || true
ip link delete $TAP_DEV 2>/dev/null || true

echo "[FirmSight] Virtual network interfaces removed cleanly."
