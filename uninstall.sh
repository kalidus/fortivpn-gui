#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${HOME}/.local/share/fortivpn-gui"
BIN_FILE="${HOME}/.local/bin/fortivpn-gui"
APPS_DIR="${HOME}/.local/share/applications"
DESKTOP_FILE="${APPS_DIR}/fortivpn-gui.desktop"
CONFIG_DIR="${HOME}/.config/fortivpn-gui"

echo "=== Desinstalador de FortiVPN GUI ==="

rm -rf "${INSTALL_DIR}"
rm -f "${BIN_FILE}"
rm -f "${DESKTOP_FILE}"

# Eliminar acceso directo del escritorio si existe
for candidate in \
    "$(command -v xdg-user-dir >/dev/null 2>&1 && xdg-user-dir DESKTOP 2>/dev/null || true)" \
    "${HOME}/Escritorio" \
    "${HOME}/Desktop"; do
    if [ -n "${candidate}" ] && [ -e "${candidate}/fortivpn-gui.desktop" -o -L "${candidate}/fortivpn-gui.desktop" ]; then
        rm -f "${candidate}/fortivpn-gui.desktop"
    fi
done

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "${APPS_DIR}" >/dev/null 2>&1 || true
fi

echo "✓ FortiVPN GUI desinstalada."
if [ -d "${CONFIG_DIR}" ]; then
    echo "ℹ Tus perfiles guardados siguen en ${CONFIG_DIR} (bórralos manualmente si no los necesitas)."
fi
