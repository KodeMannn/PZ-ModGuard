#!/usr/bin/env sh
# =================================================================
# Project Zomboid - Advanced Java & Binary Mod Guard (Linux Launcher)
# Version 2.8.0
# =================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Steam launch option:  /path/to/pz-modguard.sh --launch %command%
# Runs a Quick Scan. Only a clean result starts the game directly; anything found (or a failed scan) waits
# for the user to confirm, and anything but "Yes" cancels the launch.
if [ "$1" = "--launch" ]; then
    shift
    python3 "$SCRIPT_DIR/pz_modguard.py" --profile 1 </dev/null
    RC=$?
    if [ $RC -ne 0 ]; then
        if [ $RC -eq 20 ]; then
            MSG="PZ-ModGuard found CRITICAL THREATS in your Project Zomboid mods. Report: $SCRIPT_DIR/pz_mod_scan_report.txt"
        elif [ $RC -eq 10 ]; then
            MSG="PZ-ModGuard found suspicious items in your Project Zomboid mods. Report: $SCRIPT_DIR/pz_mod_scan_report.txt"
        else
            MSG="PZ-ModGuard could not finish the scan (exit code $RC). Is python3 installed?"
        fi
        if command -v zenity >/dev/null 2>&1; then
            zenity --question --title="PZ-ModGuard" --text="$MSG

Launch Project Zomboid anyway?" --default-cancel || exit 1
        else
            echo "$MSG" >&2
            exit 1
        fi
    fi
    exec "$@"
fi

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
