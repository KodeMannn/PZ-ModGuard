#!/usr/bin/env sh
# =================================================================
# Project Zomboid - Advanced Java & Binary Mod Guard (Linux Launcher)
# Version 2.6.0
# =================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if command -v python3 >/dev/null 2>&1; then
    python3 "$SCRIPT_DIR/pz_modguard.py" "$@"
    EXIT_CODE=$?
    
    # If launched from GUI/desktop file manager without a persistent shell, keep terminal open
    if [ -t 0 ] && [ -t 1 ]; then
        echo ""
        printf "Press [Enter] to exit..."
        read -r _
    fi
    exit $EXIT_CODE
else
    echo "\033[91m[ERROR] Python 3 is required to run PZ-ModGuard on Linux.\033[0m" >&2
    echo "Please install Python 3 via your package manager:" >&2
    echo "  Ubuntu/Debian: sudo apt install python3" >&2
    echo "  Arch/Manjaro:  sudo pacman -S python" >&2
    echo "  Fedora:        sudo dnf install python3" >&2
    echo "  SteamOS:       Python 3 is already pre-installed by default." >&2
    echo ""
    printf "Press [Enter] to exit..."
    read -r _
    exit 1
fi
