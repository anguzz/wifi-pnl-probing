#!/bin/bash

# Auto-detect first wireless interface
iface=$(iw dev | awk '$1=="Interface"{print $2}' | head -n1)

if [ -z "$iface" ]; then
  echo "No wireless interface found. Exiting."
  exit 1
fi

echo "Found interface: $iface"

# Kill interfering processes (e.g., NetworkManager, wpa_supplicant)
airmon-ng check kill

# Enable monitor mode
ip link set "$iface" down
iw dev "$iface" set type monitor
ip link set "$iface" up

# Confirm monitor mode (optional)
iw dev "$iface" info | grep -i type

# Save or update IFACE in .env
ENV_PATH="$(dirname "$0")/../.env"

if [ -f "$ENV_PATH" ]; then
  # Replace existing IFACE or append if not present
  if grep -q "^IFACE=" "$ENV_PATH"; then
    sed -i "s/^IFACE=.*/IFACE=$iface/" "$ENV_PATH"
  else
    echo "IFACE=$iface" >> "$ENV_PATH"
  fi
else
  echo "IFACE=$iface" > "$ENV_PATH"
fi

echo "Interface $iface set to monitor mode and saved to .env"
