#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "This is a program to rate your system's security measures."


rm -rvf temp
cd Assets

python3 "Linux Audit Tool.py"

cd ..

echo "Displaying Report"
cat Report/Report.txt