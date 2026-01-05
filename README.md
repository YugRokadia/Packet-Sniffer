# Packet Sniffer

A real-time network traffic analyzer with a beautiful terminal dashboard.
<img width="1257" height="697" alt="image" src="https://github.com/user-attachments/assets/ecceedc4-5d41-4f9c-b457-5c9c401d2d31" />
<img width="1257" height="688" alt="image" src="https://github.com/user-attachments/assets/4c51d1bc-d4c3-41af-a3ae-698fd82b601e" />

## Features
- 📊 Live protocol distribution analysis
- 🔝 Top talkers by traffic volume
- 🌐 HTTPS domain tracking (SNI extraction)
- 🔎 DNS query monitoring
- 📡 Recent packet stream
- 🔒 Security alerts (DNS tunneling, unencrypted protocols)
- 📄 Raw packet logs with live viewer
- 🎮 Interactive split-screen mode (up to 4 panels)
- ⏯️ Pause/Resume functionality
- 🎨 Beautiful Rich terminal UI

## Installation

### Quick Install (Ubuntu/Debian)

```bash
chmod +x install.sh
./install.sh
```

The installer will:
- Install required dependencies (libpcap, g++, Python packages)
- Compile the C++ packet capture engine
- Set up desktop application launcher
- Configure proper permissions

### Manual Installation

**Requirements:**
- Ubuntu/Debian Linux (or any Linux with apt)
- libpcap development files
- g++ compiler (C++17)
- Python 3.7+
- Python Rich library

**Steps:**
```bash
# Install system dependencies
sudo apt-get install libpcap-dev g++ python3 python3-pip

# Install Python dependencies
pip3 install rich

# Compile C++ engine
g++ -std=c++17 -o capture_engine capture_engine.cpp -lpcap

# Set permissions
sudo chown root:root capture_engine
sudo chmod u+s capture_engine

# Run
python3 dashboard.py
```

## Usage

Launch from applications menu: **Packet Sniffer**

Or run from terminal:
```bash
python3 dashboard.py
```

### Keyboard Shortcuts

Press **?** to toggle help menu

**View Controls:**
- **[P]** - Protocol breakdown
- **[T]** - Top talkers
- **[D]** - HTTPS domains
- **[N]** - DNS queries
- **[R]** - Recent packets
- **[A]** - Security alerts
- **[L]** - Raw logs panel
- **[O]** - Overview (all panels)
- **[S]** - Split screen mode (select up to 4 panels)

**Actions:**
- **[SPACE]** - Pause/Resume capture
- **[C]** - Clear all statistics
- **[V]** - View logs in new terminal (live)
- **[Q]** - Quit

### Split Screen Mode

1. Press **[S]** to enter split mode
2. Press panel keys to add: **[P] [T] [D] [N]** etc.
3. Add 1-4 panels to create custom layout
4. Press **[S]** again to exit, or **[O]** for overview

## Architecture

- **C++ Capture Engine** (`capture_engine.cpp`) - High-performance packet capture using libpcap
- **Python Dashboard** (`dashboard.py`) - Real-time terminal UI using Rich library
- **Communication** - JSON over stdout/stdin

## Security Detection

Current alerts:
- **DNS Tunneling** - Detects suspicious long DNS queries (data exfiltration)
- **Unencrypted Protocols** - Flags FTP and other insecure traffic

## Compatibility

- ✅ Ubuntu/Debian/Mint
- ✅ Fedora/RHEL/CentOS
- ✅ Arch Linux
- ✅ Raspberry Pi
- ⚠️ Windows - Use WSL2
- ⚠️ macOS - Requires modifications

## Uninstall

```bash
rm -rf ~/.local/share/packet-sniffer
rm ~/.local/share/applications/packet-sniffer.desktop
```

## License

MIT License

Copyright (c) 2025 superCoder471

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Contributing

Feel free to submit issues and pull requests!
