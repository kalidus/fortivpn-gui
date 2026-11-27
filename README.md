# FortiVPN GUI

Cliente gráfico compacto y ligero para **OpenFortiVPN** en Linux (PyQt6), con acceso directo en el Escritorio, lanzador en terminal (`fortivpn-gui`) e icono en la bandeja del sistema.

## Características
- Selector de múltiples perfiles/archivos `.conf` (o creación de un `.conf` nuevo desde la propia interfaz).
- Introducción rápida de **usuario**, **contraseña** y **token (OTP / 2FA)**.
- Icono compacto de **certificados** para elegir `ca-file`, `user-cert` (incluido `pkcs11:`), `user-key`, passphrase PEM y huellas `trusted-cert` (con obtención automática de la huella SHA-256 del servidor).
- **Vista compacta al conectar**: oculta los campos de acceso y muestra solo la URL del servidor, el icono de certificados, la **IP VPN** (copiable con un clic) y el tráfico en tiempo real (`↓ recibido` / `↑ enviado`).
- Detección automática de certificados no verificados (`trusted-cert`) con opción de confiar y reconectar en un clic.
- Elevación segura mediante `pkexec` sin exponer contraseñas ni tokens en la lista de procesos (`ps`) y desconexión limpia sin volver a pedir contraseña.
- Icono en la bandeja del sistema con estado (conectado/conectando/desconectado), temporizador, IP asignada y tráfico.

## Instalación rápida (en cualquier Linux)

Un solo comando (detecta `apt`, `dnf`, `pacman` o `zypper` y ofrece instalar automáticamente `openfortivpn`, `PyQt6` y `polkit`):

```bash
curl -fsSL https://raw.githubusercontent.com/kalidus/fortivpn-gui/main/install.sh | bash
```

Si ya tienes un archivo `.conf` y quieres dejarlo preconfigurado al instalar:

```bash
curl -fsSL https://raw.githubusercontent.com/kalidus/fortivpn-gui/main/install.sh | bash -s -- /ruta/a/tu_vpn.conf
```

### Instalación manual desde Git

```bash
git clone https://github.com/kalidus/fortivpn-gui.git
cd fortivpn-gui
./install.sh
```

Tras instalar, puedes abrir **FortiVPN** desde el icono del Escritorio, desde el menú de aplicaciones o ejecutando `fortivpn-gui` en la terminal.

## Requisitos previos
El instalador intenta instalarlos automáticamente, pero también puedes hacerlo a mano:

- **Ubuntu / Debian / Linux Mint:**
  ```bash
  sudo apt install openfortivpn python3-pyqt6 python3-pyqt6.qtsvg pkexec
  ```
- **Arch / Manjaro / EndeavourOS:**
  ```bash
  sudo pacman -S openfortivpn python-pyqt6 polkit
  ```
- **Fedora / RHEL:**
  ```bash
  sudo dnf install openfortivpn python3-pyqt6 polkit
  ```
- **openSUSE:**
  ```bash
  sudo zypper install openfortivpn python3-qt6 polkit
  ```

## Desinstalación

```bash
~/.local/share/fortivpn-gui/uninstall.sh
```

*(o `./uninstall.sh` desde la carpeta clonada)*. Los archivos `.conf` originales de tu VPN nunca se eliminan.
