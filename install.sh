#!/usr/bin/env bash
set -euo pipefail

REPO_RAW_URL="${FORTIVPN_GUI_RAW_URL:-https://raw.githubusercontent.com/kalidus/fortivpn-gui/main}"
INSTALL_DIR="${HOME}/.local/share/fortivpn-gui"
BIN_DIR="${HOME}/.local/bin"
BIN_FILE="${BIN_DIR}/fortivpn-gui"
APPS_DIR="${HOME}/.local/share/applications"
DESKTOP_FILE="${APPS_DIR}/fortivpn-gui.desktop"
CONFIG_DIR="${HOME}/.config/fortivpn-gui"
SETTINGS_FILE="${CONFIG_DIR}/settings.json"

AUTO_YES=false
CONF_ARG=""

for arg in "$@"; do
    case "${arg}" in
        -y|--yes)
            AUTO_YES=true
            ;;
        -h|--help)
            echo "Uso: $0 [-y|--yes] [/ruta/a/tu_vpn.conf]"
            exit 0
            ;;
        *)
            if [ -z "${CONF_ARG}" ]; then
                CONF_ARG="${arg}"
            fi
            ;;
    esac
done

echo "=== Instalador de FortiVPN GUI ==="
echo

prompt_yn() {
    local prompt="$1"
    local default="${2:-n}"
    if [ "${AUTO_YES}" = true ]; then
        return 0
    fi
    local reply=""
    if [ -t 0 ]; then
        read -r -p "${prompt} " reply || reply=""
    elif [ -r /dev/tty ]; then
        read -r -p "${prompt} " reply </dev/tty || reply=""
    else
        reply="${default}"
    fi
    reply="${reply:-${default}}"
    [[ "${reply}" =~ ^[sSyY]$ ]]
}

has_openfortivpn() {
    command -v openfortivpn >/dev/null 2>&1 \
        || [ -x /usr/sbin/openfortivpn ] \
        || [ -x /usr/local/sbin/openfortivpn ]
}

check_missing_deps() {
    MISSING=()
    if ! command -v python3 >/dev/null 2>&1; then
        MISSING+=("python3")
    fi
    if ! has_openfortivpn; then
        MISSING+=("openfortivpn")
    fi
    if ! command -v pkexec >/dev/null 2>&1; then
        MISSING+=("polkit (pkexec)")
    fi
    if command -v python3 >/dev/null 2>&1; then
        if ! python3 -c "import PyQt6.QtWidgets, PyQt6.QtSvg, PyQt6.QtNetwork" >/dev/null 2>&1; then
            MISSING+=("PyQt6 (QtWidgets, QtSvg, QtNetwork)")
        fi
    fi
}

install_system_deps() {
    local sudo_cmd=""
    if [ "$(id -u)" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            sudo_cmd="sudo"
        else
            echo "✗ No se encontró 'sudo'. Instala las dependencias manualmente como root."
            return 1
        fi
    fi

    if command -v apt-get >/dev/null 2>&1; then
        local polkit_pkg="pkexec"
        if ! apt-cache show pkexec >/dev/null 2>&1; then
            polkit_pkg="policykit-1"
        fi
        echo "→ Instalando dependencias con apt..."
        ${sudo_cmd} apt-get update
        ${sudo_cmd} apt-get install -y openfortivpn python3-pyqt6 python3-pyqt6.qtsvg "${polkit_pkg}"
    elif command -v dnf >/dev/null 2>&1; then
        echo "→ Instalando dependencias con dnf..."
        ${sudo_cmd} dnf install -y openfortivpn python3-pyqt6 polkit
    elif command -v pacman >/dev/null 2>&1; then
        echo "→ Instalando dependencias con pacman..."
        ${sudo_cmd} pacman -S --needed --noconfirm openfortivpn python-pyqt6 polkit
    elif command -v zypper >/dev/null 2>&1; then
        echo "→ Instalando dependencias con zypper..."
        ${sudo_cmd} zypper --non-interactive install openfortivpn python3-qt6 polkit
    else
        echo "⚠ No se reconoció el gestor de paquetes de esta distribución."
        return 1
    fi
}

# 1. Comprobar e instalar dependencias si faltan
MISSING=()
check_missing_deps

if [ ${#MISSING[@]} -gt 0 ]; then
    echo "⚠ Faltan algunas dependencias en este equipo:"
    for dep in "${MISSING[@]}"; do
        echo "  - ${dep}"
    done
    echo

    if prompt_yn "¿Instalar automáticamente las dependencias faltantes ahora? [S/n]" "s"; then
        if ! install_system_deps; then
            echo
            echo "Instálalas manualmente según tu distribución:"
            echo "  • Ubuntu / Debian / Mint: sudo apt install openfortivpn python3-pyqt6 python3-pyqt6.qtsvg pkexec"
            echo "  • Arch / Manjaro:         sudo pacman -S openfortivpn python-pyqt6 polkit"
            echo "  • Fedora / RHEL:          sudo dnf install openfortivpn python3-pyqt6 polkit"
            echo "  • openSUSE:               sudo zypper install openfortivpn python3-qt6 polkit"
            echo
            if ! prompt_yn "¿Continuar con la instalación de todos modos? [s/N]" "n"; then
                echo "Instalación cancelada."
                exit 1
            fi
        else
            check_missing_deps
            if [ ${#MISSING[@]} -gt 0 ]; then
                echo "⚠ Siguen faltando: ${MISSING[*]}"
                if ! prompt_yn "¿Continuar con la instalación de todos modos? [s/N]" "n"; then
                    echo "Instalación cancelada."
                    exit 1
                fi
            fi
        fi
    else
        echo "  • Ubuntu / Debian / Mint: sudo apt install openfortivpn python3-pyqt6 python3-pyqt6.qtsvg pkexec"
        echo "  • Arch / Manjaro:         sudo pacman -S openfortivpn python-pyqt6 polkit"
        echo "  • Fedora / RHEL:          sudo dnf install openfortivpn python3-pyqt6 polkit"
        echo "  • openSUSE:               sudo zypper install openfortivpn python3-qt6 polkit"
        echo
        if ! prompt_yn "¿Continuar con la instalación de todos modos? [s/N]" "n"; then
            echo "Instalación cancelada."
            exit 1
        fi
    fi
fi

# 2. Localizar o descargar los archivos fuente (soporta ./install.sh y curl | bash)
SRC_DIR=""
TMP_DIR=""
cleanup() {
    if [ -n "${TMP_DIR}" ] && [ -d "${TMP_DIR}" ]; then
        rm -rf "${TMP_DIR}"
    fi
}
trap cleanup EXIT

if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    CANDIDATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "${CANDIDATE_DIR}/fortivpn_gui.py" ] && [ -f "${CANDIDATE_DIR}/vpn_runner.py" ]; then
        SRC_DIR="${CANDIDATE_DIR}"
    fi
fi

if [ -z "${SRC_DIR}" ]; then
    echo "→ Descargando archivos desde GitHub (${REPO_RAW_URL})..."
    TMP_DIR="$(mktemp -d)"
    SRC_DIR="${TMP_DIR}"
    for fname in fortivpn_gui.py vpn_runner.py icon.svg uninstall.sh; do
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL "${REPO_RAW_URL}/${fname}" -o "${TMP_DIR}/${fname}"
        elif command -v wget >/dev/null 2>&1; then
            wget -qO "${TMP_DIR}/${fname}" "${REPO_RAW_URL}/${fname}"
        else
            echo "✗ Se necesita 'curl' o 'wget' para descargar los archivos."
            exit 1
        fi
    done
fi

PYTHON_BIN="$(command -v python3 || echo /usr/bin/python3)"

# 3. Copiar archivos de la aplicación
mkdir -p "${INSTALL_DIR}" "${BIN_DIR}" "${APPS_DIR}"
install -m 755 "${SRC_DIR}/fortivpn_gui.py" "${INSTALL_DIR}/fortivpn_gui.py"
install -m 755 "${SRC_DIR}/vpn_runner.py" "${INSTALL_DIR}/vpn_runner.py"
install -m 644 "${SRC_DIR}/icon.svg" "${INSTALL_DIR}/icon.svg"
if [ -f "${SRC_DIR}/uninstall.sh" ]; then
    install -m 755 "${SRC_DIR}/uninstall.sh" "${INSTALL_DIR}/uninstall.sh"
fi

# 4. Crear lanzador CLI en ~/.local/bin/fortivpn-gui
cat > "${BIN_FILE}" <<EOF
#!/usr/bin/env bash
exec "${PYTHON_BIN}" "${INSTALL_DIR}/fortivpn_gui.py" "\$@"
EOF
chmod 755 "${BIN_FILE}"

# 5. Crear lanzador .desktop
cat > "${DESKTOP_FILE}" <<EOF
[Desktop Entry]
Type=Application
Name=FortiVPN
GenericName=Cliente VPN OpenFortiVPN
Comment=Conectar a la VPN con OpenFortiVPN (conexión, contraseña, token y certificados)
Exec=${PYTHON_BIN} ${INSTALL_DIR}/fortivpn_gui.py
Icon=${INSTALL_DIR}/icon.svg
Terminal=false
Categories=Network;
Keywords=vpn;openfortivpn;fortinet;token;otp;
StartupWMClass=fortivpn-gui
EOF
chmod 755 "${DESKTOP_FILE}"

# 6. Crear acceso directo en el Escritorio (Escritorio / Desktop)
DESKTOP_DIR=""
if command -v xdg-user-dir >/dev/null 2>&1; then
    DESKTOP_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || true)"
fi
if [ -z "${DESKTOP_DIR}" ] || [ ! -d "${DESKTOP_DIR}" ]; then
    if [ -d "${HOME}/Escritorio" ]; then
        DESKTOP_DIR="${HOME}/Escritorio"
    elif [ -d "${HOME}/Desktop" ]; then
        DESKTOP_DIR="${HOME}/Desktop"
    fi
fi

if [ -n "${DESKTOP_DIR}" ] && [ -d "${DESKTOP_DIR}" ]; then
    SHORTCUT="${DESKTOP_DIR}/fortivpn-gui.desktop"
    ln -sf "${DESKTOP_FILE}" "${SHORTCUT}"
    if command -v gio >/dev/null 2>&1; then
        gio set "${SHORTCUT}" metadata::trusted true 2>/dev/null || true
    fi
    echo "✓ Acceso directo creado en: ${SHORTCUT}"
else
    echo "ℹ No se detectó carpeta de Escritorio; la app estará disponible en el menú de aplicaciones."
fi

# 7. Si se pasó un archivo .conf como argumento, preconfigurarlo
if [ -n "${CONF_ARG}" ] && [ -f "${CONF_ARG}" ]; then
    CONF_ABS="$(cd "$(dirname "${CONF_ARG}")" && pwd)/$(basename "${CONF_ARG}")"
    if [ ! -f "${SETTINGS_FILE}" ]; then
        mkdir -p "${CONFIG_DIR}"
        "${PYTHON_BIN}" - "${CONF_ABS}" "${SETTINGS_FILE}" <<'PY'
import json, pathlib, sys
conf_path = sys.argv[1]
settings_path = pathlib.Path(sys.argv[2])
name = pathlib.Path(conf_path).stem.replace("_", " ").replace("-", " ").title()
data = {"profiles": [{"name": name, "path": conf_path}], "selected": 0}
settings_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
PY
        echo "✓ Configuración inicial añadida: ${CONF_ABS}"
    fi
fi

# 8. Refrescar base de datos de aplicaciones
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "${APPS_DIR}" >/dev/null 2>&1 || true
fi

echo "✓ FortiVPN instalada en: ${INSTALL_DIR}"
echo "✓ Lanzador CLI creado en: ${BIN_FILE}"
echo
echo "¡Listo! Ya puedes abrir FortiVPN desde el Escritorio, el menú de aplicaciones o ejecutando 'fortivpn-gui'."
