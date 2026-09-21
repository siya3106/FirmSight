#!/usr/bin/env bash
# FirmSight Virtual Network Isolation Setup Script
set -e

TAP_DEV="tap0"
BR_DEV="br0"
HOST_IP="192.168.1.1/24"

echo "[FirmSight] Creating virtual TAP interface: $TAP_DEV"
ip tuntap add mode tap $TAP_DEV
ip link set $TAP_DEV up

echo "[FirmSight] Creating bridge interface: $BR_DEV"
ip link add name $BR_DEV type bridge
ip link set $TAP_DEV master $BR_DEV
ip addr add $HOST_IP dev $BR_DEV
ip link set $BR_DEV up

echo "[FirmSight] Network sandbox bridge active at $HOST_IP"
