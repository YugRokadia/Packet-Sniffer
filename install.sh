#!/bin/bash
# Packet Sniffer - One-Click Installer for Ubuntu/Debian

set -e  # Exit on error

echo "=========================================="
echo "  Packet Sniffer Installer"
echo "=========================================="
echo ""

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "Error: This installer only works on Linux."
    exit 1
fi

# Get installation directory
INSTALL_DIR="$HOME/.local/share/packet-sniffer"
echo "Installing to: $INSTALL_DIR"

# Install system dependencies
echo ""
echo "[1/6] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y libpcap-dev g++ python3 python3-pip zenity 2>&1 | grep -v "already"

# Install Python dependencies
echo ""
echo "[2/6] Installing Python dependencies..."
pip3 install rich --quiet --user

# Create installation directory
echo ""
echo "[3/6] Creating installation directory..."
mkdir -p "$INSTALL_DIR"

# Copy files
echo ""
echo "[4/6] Copying files..."
cp capture_engine.cpp "$INSTALL_DIR/"
cp dashboard.py "$INSTALL_DIR/"
cp run.sh "$INSTALL_DIR/"
cp icon.png "$INSTALL_DIR/" 2>/dev/null || echo "   (No icon found, using default)"

# Compile C++ engine
echo ""
echo "[5/6] Compiling packet capture engine..."
cd "$INSTALL_DIR"
g++ -std=c++17 -o capture_engine capture_engine.cpp -lpcap

# Set permissions
echo "   Setting permissions (requires sudo)..."
sudo chown root:root capture_engine
sudo chmod u+s capture_engine

# Install desktop entry
echo ""
echo "[6/6] Installing desktop application..."
cat > "$HOME/.local/share/applications/packet-sniffer.desktop" << EOF
[Desktop Entry]
Name=Packet Sniffer
Comment=Network Traffic Analyzer with Real-time Dashboard
Exec=$INSTALL_DIR/run.sh
Icon=$INSTALL_DIR/icon.png
Terminal=true
Type=Application
Categories=Network;System;Security;
Keywords=network;packet;sniffer;monitor;security;
StartupNotify=true
EOF

chmod +x "$HOME/.local/share/applications/packet-sniffer.desktop"
chmod +x "$INSTALL_DIR/run.sh"

echo ""
echo "=========================================="
echo "  Installation Complete! ✓"
echo "=========================================="
echo ""
echo "To launch:"
echo "  1. Press Super key and search 'Packet Sniffer'"
echo "  2. Or run: $INSTALL_DIR/run.sh"
echo ""
echo "To uninstall:"
echo "  rm -rf $INSTALL_DIR"
echo "  rm ~/.local/share/applications/packet-sniffer.desktop"
echo ""
