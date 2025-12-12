#!/bin/bash
# Packet Sniffer Runner Script

cd "$(dirname "$0")"

# Check dependencies
if [ ! -f "./capture_engine" ]; then
    zenity --error --text="capture_engine not found! Please compile first." --width=300
    exit 1
fi

if ! python3 -c "import rich" 2>/dev/null; then
    zenity --error --text="Python 'rich' library not installed!\n\nRun: pip3 install rich" --width=300
    exit 1
fi

# Run the dashboard
python3 dashboard.py
