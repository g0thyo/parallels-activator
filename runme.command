#!/bin/bash
# Double-click installer for the Parallels Desktop activator.
# Opens Terminal, asks for your password once, runs the full pipeline.
cd "$(dirname "$0")"
sudo python3 ./parallels_activator.py
echo
read -n 1 -s -r -p "Press any key to close..."
echo
