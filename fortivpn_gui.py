#!/usr/bin/env python3
"""FortiVPN GUI — Cliente gráfico compacto para OpenFortiVPN (PyQt6 / KDE)."""

import fcntl
import hashlib
import json
import math
import os
import shutil
import socket
import ssl
import struct
import sys
import time
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import (
    QEvent,
    QPointF,
    QProcess,
    QRectF,
    QSize,
    Qt,
    QTimer,
)
from PyQt6.QtGui import (
    QAction,
    QColor,
    QFont,
    QFontMetricsF,
    QIcon,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)
from PyQt6.QtNetwork import QLocalServer, QLocalSocket
from PyQt6.QtSvg import QSvgRenderer
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSystemTrayIcon,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

APP_NAME = "FortiVPN"
APP_DIR = Path(__file__).resolve().parent
RUNNER_PATH = APP_DIR / "vpn_runner.py"
ICON_PATH = APP_DIR / "icon.svg"
CONFIG_DIR = Path.home() / ".config" / "fortivpn-gui"
SETTINGS_FILE = CONFIG_DIR / "settings.json"
DEFAULT_CONF_CANDIDATES = [
    ("OpenFortiVPN (sistema)", "/etc/openfortivpn/config"),
]
IPC_SERVER_NAME = f"fortivpn-gui-{os.getuid()}"


def parse_openfortivpn_conf(path: str) -> dict:
    """Parse metadata and certificate settings from an openfortivpn config file."""
    info = {
        "exists": False,
        "readable": False,
        "writable": False,
        "host": "",
        "port": "",
        "username": "",
        "has_password": False,
        "ca_file": "",
        "user_cert": "",
        "user_key": "",
        "has_pem_passphrase": False,
        "trusted_certs": [],
        "error": "",
    }
    if not path:
        return info

    p = Path(path)
    try:
        info["exists"] = p.exists()
    except OSError:
        info["exists"] = False

    if not info["exists"]:
        return info

    info["writable"] = os.access(p, os.W_OK)

    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            info["readable"] = True
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip().lower()
                val = val.strip()
                if key == "host":
                    info["host"] = val
                elif key == "port":
                    info["port"] = val
                elif key == "username":
                    info["username"] = val
                elif key == "password" and val:
                    info["has_password"] = True
                elif key == "ca-file":
                    info["ca_file"] = val
                elif key == "user-cert":
                    info["user_cert"] = val
                elif key == "user-key":
                    info["user_key"] = val
                elif key == "pem-passphrase" and val:
                    info["has_pem_passphrase"] = True
                elif key == "trusted-cert" and val:
                    if val not in info["trusted_certs"]:
                        info["trusted_certs"].append(val)
    except PermissionError:
        info["readable"] = False
        info["error"] = "permiso"
    except OSError as exc:
        info["readable"] = False
        info["error"] = str(exc)

    return info


def update_openfortivpn_conf(path: str, cert_updates: dict) -> None:
    """Update certificate keys in an openfortivpn .conf file preserving comments and other keys."""
    p = Path(path)
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)

    single_keys = {}
    for key in ("ca-file", "user-cert", "user-key"):
        if key in cert_updates:
            single_keys[key] = str(cert_updates[key] or "").strip()

    trusted_certs = None
    if "trusted-cert" in cert_updates and isinstance(cert_updates["trusted-cert"], list):
        trusted_certs = [str(c).strip() for c in cert_updates["trusted-cert"] if str(c).strip()]

    keys_to_replace = set(single_keys.keys())
    if trusted_certs is not None:
        keys_to_replace.add("trusted-cert")

    out_lines = []
    for raw in lines:
        stripped = raw.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k = stripped.split("=", 1)[0].strip().lower()
            if k in keys_to_replace:
                continue
        out_lines.append(raw)

    if out_lines and not out_lines[-1].endswith("\n"):
        out_lines.append("\n")

    for key, val in single_keys.items():
        if val:
            out_lines.append(f"{key} = {val}\n")

    if trusted_certs is not None:
        for digest in trusted_certs:
            out_lines.append(f"trusted-cert = {digest}\n")

    p.write_text("".join(out_lines), encoding="utf-8")


def fetch_server_cert_sha256(host: str, port: int = 443, timeout: float = 6.0) -> str:
    """Connect to host:port over TLS and return leaf certificate SHA-256 hex digest."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
            der = tls_sock.getpeercert(binary_form=True)
            if not der:
                raise RuntimeError("El servidor no devolvió ningún certificado.")
            return hashlib.sha256(der).hexdigest().lower()


def effective_cert_settings(profile: dict, conf_meta: dict) -> dict:
    """Merge certificate settings from .conf with any per-profile GUI overrides."""
    overrides = profile.get("cert_overrides")
    if not isinstance(overrides, dict):
        overrides = {}

    ca_file = overrides["ca-file"] if "ca-file" in overrides else conf_meta.get("ca_file", "")
    user_cert = overrides["user-cert"] if "user-cert" in overrides else conf_meta.get("user_cert", "")
    user_key = overrides["user-key"] if "user-key" in overrides else conf_meta.get("user_key", "")
    trusted = (
        list(overrides["trusted-cert"])
        if "trusted-cert" in overrides and isinstance(overrides["trusted-cert"], list)
        else list(conf_meta.get("trusted_certs", []))
    )
    return {
        "ca-file": str(ca_file or "").strip(),
        "user-cert": str(user_cert or "").strip(),
        "user-key": str(user_key or "").strip(),
        "trusted-cert": [str(c).strip() for c in trusted if str(c).strip()],
    }


def build_status_icon(dot_color: str | None = None) -> QIcon:
    """Render SVG icon with optional colored status indicator dot."""
    size = 64
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    if ICON_PATH.is_file():
        renderer = QSvgRenderer(str(ICON_PATH))
        renderer.render(painter)
    else:
        painter.setBrush(QColor("#2563eb"))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(4, 4, 56, 56, 14, 14)

    if dot_color:
        painter.setBrush(QColor("#ffffff"))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(38, 38, 24, 24)
        painter.setBrush(QColor(dot_color))
        painter.drawEllipse(41, 41, 18, 18)

    painter.end()
    return QIcon(pixmap)


def build_cert_icon(configured: bool = False) -> QIcon:
    """Render a crisp vector shield/certificate icon."""
    size = 48
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    path = QPainterPath()
    path.moveTo(24.0, 5.0)
    path.lineTo(40.0, 11.5)
    path.lineTo(40.0, 23.0)
    path.cubicTo(40.0, 33.5, 32.5, 40.5, 24.0, 43.5)
    path.cubicTo(15.5, 40.5, 8.0, 33.5, 8.0, 23.0)
    path.lineTo(8.0, 11.5)
    path.closeSubpath()

    if configured:
        fill = QColor(34, 197, 94, 48)
        stroke = QColor("#22c55e")
    else:
        fill = QColor(148, 163, 184, 28)
        stroke = QColor("#94a3b8")

    painter.setBrush(fill)
    painter.setPen(
        QPen(stroke, 3.0, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
    )
    painter.drawPath(path)

    if configured:
        check = QPainterPath()
        check.moveTo(16.5, 24.5)
        check.lineTo(22.0, 30.0)
        check.lineTo(32.0, 18.5)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(
            QPen(stroke, 3.4, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
        )
        painter.drawPath(check)
    else:
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(
            QPen(stroke, 2.6, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
        )
        painter.drawArc(QRectF(19.0, 15.5, 10.0, 10.0), 0, 180 * 16)
        painter.setBrush(stroke)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(QRectF(17.5, 21.5, 13.0, 10.5), 2.5, 2.5)

    painter.end()
    return QIcon(pixmap)


def build_globe_pixmap(size: int = 14, color: str = "#64748b") -> QPixmap:
    """Render a crisp monochrome globe icon for server URLs."""
    scale = 3
    px = size * scale
    pixmap = QPixmap(px, px)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    c = QColor(color)
    pen = QPen(c, 1.45 * scale, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)

    m = 2.0 * scale
    rect = QRectF(m, m, px - 2 * m, px - 2 * m)
    painter.drawEllipse(rect)
    # Meridian ellipse
    meridian = QRectF(px * 0.31, m, px * 0.38, px - 2 * m)
    painter.drawEllipse(meridian)
    # Equator line
    painter.drawLine(QPointF(m, px / 2.0), QPointF(px - m, px / 2.0))

    painter.end()
    pixmap.setDevicePixelRatio(scale)
    return pixmap


def get_iface_ipv4(iface: str) -> str:
    """Return IPv4 address assigned to a Linux network interface, or empty string."""
    if not iface:
        return ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            ifreq = struct.pack("256s", iface[:15].encode("ascii", errors="ignore"))
            res = fcntl.ioctl(s.fileno(), 0x8915, ifreq)  # SIOCGIFADDR
            return socket.inet_ntoa(res[20:24])
    except OSError:
        return ""


def detect_vpn_iface(expected_ip: str = "") -> str:
    """Detect the active VPN tunnel interface (typically ppp0) from /sys/class/net."""
    net_dir = Path("/sys/class/net")
    try:
        names = sorted(p.name for p in net_dir.iterdir() if p.name != "lo")
    except OSError:
        return ""

    vpn_prefixes = ("ppp", "tun", "vpn", "forti")
    vpn_candidates = [n for n in names if n.startswith(vpn_prefixes)]

    if expected_ip:
        for name in vpn_candidates + [n for n in names if n not in vpn_candidates]:
            if get_iface_ipv4(name) == expected_ip:
                return name

    ppp_candidates = [n for n in vpn_candidates if n.startswith("ppp")]
    if ppp_candidates:
        return ppp_candidates[-1]
    if vpn_candidates:
        return vpn_candidates[-1]
    return ""


def read_iface_bytes(iface: str) -> tuple[int, int] | None:
    """Read (rx_bytes, tx_bytes) for a Linux network interface."""
    if not iface:
        return None
    stats_dir = Path("/sys/class/net") / iface / "statistics"
    try:
        rx = int((stats_dir / "rx_bytes").read_text(encoding="ascii").strip())
        tx = int((stats_dir / "tx_bytes").read_text(encoding="ascii").strip())
        return rx, tx
    except (OSError, ValueError):
        pass

    try:
        with open("/proc/net/dev", "r", encoding="ascii", errors="ignore") as f:
            for line in f:
                if ":" not in line:
                    continue
                dev, rest = line.split(":", 1)
                if dev.strip() == iface:
                    cols = rest.split()
                    if len(cols) >= 9:
                        return int(cols[0]), int(cols[8])
    except (OSError, ValueError):
        pass
    return None


def format_bytes(num_bytes: int) -> str:
    """Format byte counts into compact human-readable strings."""
    val = float(max(0, num_bytes))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if val < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(val)} B"
            if val >= 100.0:
                return f"{val:.1f} {unit}"
            return f"{val:.2f} {unit}"
        val /= 1024.0
    return "0 B"


class StatusBadge(QWidget):
    """Custom pill status badge with tabular digits so timer updates never jitter or clip."""

    _THEMES = {
        "disconnected": (QColor(100, 116, 139, 56), QColor("#94a3b8"), "Desconectado"),
        "connecting": (QColor(245, 158, 11, 51), QColor("#f59e0b"), "Conectando..."),
        "connected": (QColor(34, 197, 94, 51), QColor("#22c55e"), "Conectado"),
        "disconnecting": (QColor(245, 158, 11, 51), QColor("#f59e0b"), "Desconectando..."),
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self._bg_color, self._fg_color, self._status_text = self._THEMES["disconnected"]
        self._elapsed_text = ""
        self._cached_size = QSize()
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self._recompute_size()

    def _badge_font(self) -> QFont:
        font = QFont(self.font())
        font.setPixelSize(12)
        font.setWeight(QFont.Weight.DemiBold)
        return font

    def _tabular_metrics(self, fm: QFontMetricsF) -> tuple[float, float]:
        digit_w = max(fm.horizontalAdvance(ch) for ch in "0123456789")
        colon_w = fm.horizontalAdvance(":")
        return digit_w, colon_w

    def _elapsed_width(self, fm: QFontMetricsF, text: str) -> float:
        digit_w, colon_w = self._tabular_metrics(fm)
        return sum(digit_w if ch.isdigit() else colon_w for ch in text)

    def _recompute_size(self):
        fm = QFontMetricsF(self._badge_font())
        pad_x = 11.0
        pad_y = 5.0
        dot_area = 7.0 + 6.0  # dot diameter + gap
        width = pad_x * 2 + dot_area + fm.horizontalAdvance(self._status_text)
        if self._elapsed_text:
            width += fm.horizontalAdvance(" · ") + self._elapsed_width(fm, self._elapsed_text)
        height = max(24.0, fm.height() + pad_y * 2)
        new_size = QSize(int(math.ceil(width)) + 2, int(math.ceil(height)))
        if new_size != self._cached_size:
            self._cached_size = new_size
            self.setFixedSize(new_size)
            self.updateGeometry()

    def sizeHint(self) -> QSize:
        return self._cached_size

    def minimumSizeHint(self) -> QSize:
        return self._cached_size

    def set_status(self, state: str, elapsed: str = ""):
        bg, fg, label = self._THEMES.get(state, self._THEMES["disconnected"])
        changed_layout = (
            label != self._status_text
            or len(elapsed) != len(self._elapsed_text)
        )
        self._bg_color = bg
        self._fg_color = fg
        self._status_text = label
        self._elapsed_text = elapsed
        if changed_layout:
            self._recompute_size()
        self.update()

    def set_elapsed(self, elapsed: str):
        if elapsed == self._elapsed_text:
            return
        changed_len = len(elapsed) != len(self._elapsed_text)
        self._elapsed_text = elapsed
        if changed_len:
            self._recompute_size()
        self.update()

    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() in (
            QEvent.Type.FontChange,
            QEvent.Type.ApplicationFontChange,
            QEvent.Type.PaletteChange,
        ):
            self._recompute_size()
            self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)

        rect = QRectF(self.rect())
        radius = rect.height() / 2.0

        # Background pill
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(self._bg_color)
        painter.drawRoundedRect(rect, radius, radius)

        # Crisp status dot
        dot_d = 7.0
        x = 11.0
        dot_y = (rect.height() - dot_d) / 2.0
        painter.setBrush(self._fg_color)
        painter.drawEllipse(QRectF(x, dot_y, dot_d, dot_d))
        x += dot_d + 6.0

        # Status text + tabular elapsed digits
        font = self._badge_font()
        painter.setFont(font)
        painter.setPen(self._fg_color)
        fm = QFontMetricsF(font)
        baseline_y = (rect.height() + fm.ascent() - fm.descent()) / 2.0

        painter.drawText(QPointF(x, baseline_y), self._status_text)
        x += fm.horizontalAdvance(self._status_text)

        if self._elapsed_text:
            sep = " · "
            painter.drawText(QPointF(x, baseline_y), sep)
            x += fm.horizontalAdvance(sep)

            digit_w, colon_w = self._tabular_metrics(fm)
            for ch in self._elapsed_text:
                cell_w = digit_w if ch.isdigit() else colon_w
                ch_w = fm.horizontalAdvance(ch)
                painter.drawText(QPointF(x + (cell_w - ch_w) / 2.0, baseline_y), ch)
                x += cell_w

        painter.end()


class CertsDialog(QDialog):
    """Dialog to choose CA cert, client cert/key, passphrase, and trusted-cert SHA-256."""

    def __init__(
        self,
        parent=None,
        conf_path: str = "",
        conf_meta: dict | None = None,
        current_certs: dict | None = None,
        pem_passphrase: str = "",
    ):
        super().__init__(parent)
        self.setWindowTitle("Certificados de la conexión")
        self.setMinimumWidth(520)

        self.conf_path = conf_path
        self.conf_meta = conf_meta or parse_openfortivpn_conf(conf_path)
        certs = current_certs or {}

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # Client & CA certificate files
        files_box = QGroupBox("Archivos de certificado (opcionales)")
        files_form = QFormLayout(files_box)
        files_form.setSpacing(8)

        self.ca_edit = QLineEdit(certs.get("ca-file", ""))
        self.ca_edit.setPlaceholderText("Ej: /ruta/ca-bundle.pem (vacío = almacén del sistema)")
        self.ca_edit.setClearButtonEnabled(True)
        files_form.addRow(
            "Certificado CA (ca-file):",
            self._file_row(
                self.ca_edit,
                "Seleccionar certificado CA",
                "Certificados (*.pem *.crt *.cer *.ca-bundle);;Todos (*)",
            ),
        )

        self.user_cert_edit = QLineEdit(certs.get("user-cert", ""))
        self.user_cert_edit.setPlaceholderText("Ej: /ruta/cliente.pem o pkcs11: (tarjeta)")
        self.user_cert_edit.setClearButtonEnabled(True)
        user_cert_row = self._file_row(
            self.user_cert_edit,
            "Seleccionar certificado de usuario",
            "Certificados (*.pem *.crt *.cer *.p12);;Todos (*)",
            extra_btn=("pkcs11:", self._set_pkcs11),
        )
        files_form.addRow("Cert. usuario (user-cert):", user_cert_row)

        self.user_key_edit = QLineEdit(certs.get("user-key", ""))
        self.user_key_edit.setPlaceholderText("Ej: /ruta/cliente-key.pem")
        self.user_key_edit.setClearButtonEnabled(True)
        files_form.addRow(
            "Clave privada (user-key):",
            self._file_row(
                self.user_key_edit,
                "Seleccionar clave privada",
                "Claves (*.pem *.key);;Todos (*)",
            ),
        )

        self.pem_pass_edit = QLineEdit(pem_passphrase)
        self.pem_pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pem_pass_edit.setPlaceholderText("Solo si la clave privada tiene contraseña (no se guarda)")
        self.pem_pass_edit.setClearButtonEnabled(True)
        files_form.addRow("Passphrase clave PEM:", self.pem_pass_edit)

        layout.addWidget(files_box)

        # Trusted server SHA-256 digests
        trust_box = QGroupBox("Certificado de confianza del servidor (trusted-cert SHA-256)")
        trust_layout = QVBoxLayout(trust_box)
        trust_layout.setSpacing(6)

        hint = QLabel("Una huella SHA-256 por línea. Déjalo vacío si confías mediante CA.")
        hint.setStyleSheet("font-size: 11px; color: #94a3b8;")
        trust_layout.addWidget(hint)

        self.trusted_edit = QPlainTextEdit()
        self.trusted_edit.setMaximumHeight(90)
        mono = QFont("monospace")
        mono.setPointSize(9)
        self.trusted_edit.setFont(mono)
        self.trusted_edit.setPlaceholderText("Ej: 4daa8c5fe6c...")
        trusted_list = certs.get("trusted-cert") or []
        if trusted_list:
            self.trusted_edit.setPlainText("\n".join(trusted_list))
        trust_layout.addWidget(self.trusted_edit)

        fetch_row = QHBoxLayout()
        self.fetch_btn = QPushButton("Obtener huella del servidor")
        self.fetch_btn.setToolTip("Conecta al servidor del .conf y lee su huella SHA-256")
        self.fetch_btn.clicked.connect(self._fetch_server_cert)
        fetch_row.addWidget(self.fetch_btn)

        clear_trust_btn = QPushButton("Limpiar")
        clear_trust_btn.clicked.connect(self.trusted_edit.clear)
        fetch_row.addWidget(clear_trust_btn)
        fetch_row.addStretch(1)
        trust_layout.addLayout(fetch_row)

        layout.addWidget(trust_box)

        # Save to .conf option
        can_write_conf = bool(self.conf_meta.get("exists") and self.conf_meta.get("writable"))
        self.save_to_conf_chk = QCheckBox(
            f"Guardar también en el archivo .conf ({Path(conf_path).name if conf_path else ''})"
        )
        self.save_to_conf_chk.setChecked(can_write_conf)
        self.save_to_conf_chk.setEnabled(can_write_conf)
        if not can_write_conf:
            self.save_to_conf_chk.setText(
                "El archivo .conf es de solo lectura: se aplicará como ajuste del perfil en la app"
            )
        layout.addWidget(self.save_to_conf_chk)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Aplicar")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Cancelar")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _file_row(self, line_edit: QLineEdit, title: str, file_filter: str, extra_btn=None):
        row = QHBoxLayout()
        row.setSpacing(6)
        row.addWidget(line_edit, 1)

        btn = QPushButton("Buscar...")
        btn.clicked.connect(lambda: self._browse_file(line_edit, title, file_filter))
        row.addWidget(btn)

        if extra_btn:
            label, callback = extra_btn
            eb = QPushButton(label)
            eb.setToolTip("Usar tarjeta inteligente / DNIe mediante PKCS#11")
            eb.clicked.connect(callback)
            row.addWidget(eb)
        return row

    def _browse_file(self, target: QLineEdit, title: str, file_filter: str):
        cur = target.text().strip()
        start_dir = ""
        if cur and not cur.startswith("pkcs11:"):
            start_dir = os.path.dirname(cur)
        if not start_dir or not os.path.isdir(start_dir):
            conf_dir = os.path.dirname(self.conf_path) if self.conf_path else ""
            start_dir = conf_dir if os.path.isdir(conf_dir) else str(Path.home())

        chosen, _ = QFileDialog.getOpenFileName(self, title, start_dir, file_filter)
        if chosen:
            target.setText(chosen)

    def _set_pkcs11(self):
        self.user_cert_edit.setText("pkcs11:")

    def _fetch_server_cert(self):
        host = self.conf_meta.get("host", "").strip()
        port_str = self.conf_meta.get("port", "").strip() or "443"
        if not host:
            host, ok = QInputDialog.getText(
                self,
                "Servidor VPN",
                "Introduce host[:puerto] del servidor VPN:",
            )
            if not ok or not host.strip():
                return
            host = host.strip()
            if ":" in host:
                host, port_str = host.rsplit(":", 1)

        try:
            port = int(port_str)
        except ValueError:
            port = 443

        self.fetch_btn.setEnabled(False)
        self.fetch_btn.setText("Consultando...")
        QApplication.processEvents()
        try:
            digest = fetch_server_cert_sha256(host, port)
            existing = [
                line.strip().lower()
                for line in self.trusted_edit.toPlainText().splitlines()
                if line.strip()
            ]
            if digest not in existing:
                existing.append(digest)
                self.trusted_edit.setPlainText("\n".join(existing))
            QMessageBox.information(
                self,
                "Huella obtenida",
                f"Servidor: {host}:{port}\n\nSHA-256:\n{digest}",
            )
        except Exception as exc:
            QMessageBox.warning(
                self,
                "No se pudo obtener el certificado",
                f"Error conectando a {host}:{port}:\n{exc}",
            )
        finally:
            self.fetch_btn.setEnabled(True)
            self.fetch_btn.setText("Obtener huella del servidor")

    def result_values(self) -> tuple[dict, str, bool]:
        trusted = [
            line.strip()
            for line in self.trusted_edit.toPlainText().splitlines()
            if line.strip()
        ]
        certs = {
            "ca-file": self.ca_edit.text().strip(),
            "user-cert": self.user_cert_edit.text().strip(),
            "user-key": self.user_key_edit.text().strip(),
            "trusted-cert": trusted,
        }
        return certs, self.pem_pass_edit.text(), self.save_to_conf_chk.isChecked()


class CreateConfDialog(QDialog):
    """Dialog to create a new openfortivpn .conf file from scratch."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Crear archivo .conf de OpenFortiVPN")
        self.setMinimumWidth(480)
        self.created_path = ""

        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.setSpacing(9)

        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("vpn.empresa.com")
        form.addRow("Servidor (host):", self.host_edit)

        self.port_edit = QLineEdit("443")
        form.addRow("Puerto:", self.port_edit)

        self.user_edit = QLineEdit()
        self.user_edit.setPlaceholderText("Opcional (se puede indicar al conectar)")
        form.addRow("Usuario:", self.user_edit)

        self.ca_edit = QLineEdit()
        self.ca_edit.setPlaceholderText("Opcional: /ruta/ca-bundle.pem")
        form.addRow("Certificado CA:", self._browse_row(self.ca_edit, "Certificados (*.pem *.crt *.cer);;Todos (*)"))

        self.user_cert_edit = QLineEdit()
        self.user_cert_edit.setPlaceholderText("Opcional: /ruta/usuario.pem o pkcs11:")
        form.addRow("Certificado usuario:", self._browse_row(self.user_cert_edit, "Certificados (*.pem *.crt *.cer);;Todos (*)"))

        self.user_key_edit = QLineEdit()
        self.user_key_edit.setPlaceholderText("Opcional: /ruta/clave.pem")
        form.addRow("Clave privada:", self._browse_row(self.user_key_edit, "Claves (*.pem *.key);;Todos (*)"))

        self.trusted_edit = QLineEdit()
        self.trusted_edit.setPlaceholderText("Opcional: huella SHA-256 (trusted-cert)")
        form.addRow("trusted-cert:", self.trusted_edit)

        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Save).setText("Guardar .conf...")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Cancelar")
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _browse_row(self, edit: QLineEdit, file_filter: str):
        row = QHBoxLayout()
        row.setSpacing(6)
        row.addWidget(edit, 1)
        btn = QPushButton("Buscar...")
        btn.clicked.connect(lambda: self._pick(edit, file_filter))
        row.addWidget(btn)
        return row

    def _pick(self, edit: QLineEdit, file_filter: str):
        chosen, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo", str(Path.home()), file_filter)
        if chosen:
            edit.setText(chosen)

    def _save(self):
        host = self.host_edit.text().strip()
        port = self.port_edit.text().strip() or "443"
        if not host:
            QMessageBox.warning(self, "Dato requerido", "Introduce el servidor (host) de la VPN.")
            self.host_edit.setFocus()
            return

        default_dir = CONFIG_DIR
        default_dir.mkdir(parents=True, exist_ok=True)
        default_file = str(default_dir / f"{host.replace('.', '_')}.conf")
        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "Guardar archivo de configuración OpenFortiVPN",
            default_file,
            "Archivos de configuración (*.conf);;Todos (*)",
        )
        if not save_path:
            return

        lines = [
            "# Configuración OpenFortiVPN generada por FortiVPN GUI\n",
            f"host = {host}\n",
            f"port = {port}\n",
        ]
        if self.user_edit.text().strip():
            lines.append(f"username = {self.user_edit.text().strip()}\n")
        if self.ca_edit.text().strip():
            lines.append(f"ca-file = {self.ca_edit.text().strip()}\n")
        if self.user_cert_edit.text().strip():
            lines.append(f"user-cert = {self.user_cert_edit.text().strip()}\n")
        if self.user_key_edit.text().strip():
            lines.append(f"user-key = {self.user_key_edit.text().strip()}\n")
        if self.trusted_edit.text().strip():
            lines.append(f"trusted-cert = {self.trusted_edit.text().strip()}\n")

        try:
            Path(save_path).write_text("".join(lines), encoding="utf-8")
            os.chmod(save_path, 0o600)
        except OSError as exc:
            QMessageBox.critical(self, "Error al guardar", str(exc))
            return

        self.created_path = save_path
        self.accept()


class ProfileDialog(QDialog):
    """Dialog to add or edit a VPN connection profile."""

    def __init__(self, parent=None, name: str = "", path: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Configurar conexión VPN")
        self.setMinimumWidth(470)

        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.setSpacing(10)

        self.name_edit = QLineEdit(name)
        self.name_edit.setPlaceholderText("Ej: VPN Empresa")
        form.addRow("Nombre:", self.name_edit)

        path_col = QVBoxLayout()
        path_col.setSpacing(6)
        path_row = QHBoxLayout()
        self.path_edit = QLineEdit(path)
        self.path_edit.setPlaceholderText("/ruta/al/archivo.conf")
        browse_btn = QPushButton("Buscar...")
        browse_btn.clicked.connect(self._browse)
        path_row.addWidget(self.path_edit, 1)
        path_row.addWidget(browse_btn)
        path_col.addLayout(path_row)

        create_btn = QPushButton("Crear nuevo archivo .conf...")
        create_btn.setFlat(True)
        create_btn.setStyleSheet("text-align: left; color: #3b82f6; padding: 2px 0;")
        create_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        create_btn.clicked.connect(self._create_new_conf)
        path_col.addWidget(create_btn)

        form.addRow("Archivo .conf:", path_col)
        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Guardar")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Cancelar")
        buttons.accepted.connect(self._validate_and_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _browse(self):
        start_dir = os.path.dirname(self.path_edit.text().strip()) or str(Path.home())
        if not os.path.isdir(start_dir):
            start_dir = str(Path.home())
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Seleccionar archivo de configuración OpenFortiVPN",
            start_dir,
            "Archivos de configuración (*.conf *.cfg *config*);;Todos los archivos (*)",
        )
        if file_path:
            self.path_edit.setText(file_path)
            if not self.name_edit.text().strip():
                stem = Path(file_path).stem.replace("_", " ").replace("-", " ").title()
                self.name_edit.setText(stem)

    def _create_new_conf(self):
        dlg = CreateConfDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted and dlg.created_path:
            self.path_edit.setText(dlg.created_path)
            if not self.name_edit.text().strip():
                stem = Path(dlg.created_path).stem.replace("_", " ").replace("-", " ").title()
                self.name_edit.setText(stem)

    def _validate_and_accept(self):
        if not self.name_edit.text().strip():
            QMessageBox.warning(self, "Dato requerido", "Introduce un nombre para la conexión.")
            self.name_edit.setFocus()
            return
        if not self.path_edit.text().strip():
            QMessageBox.warning(self, "Dato requerido", "Selecciona o crea un archivo .conf de OpenFortiVPN.")
            self.path_edit.setFocus()
            return
        self.accept()

    def values(self) -> tuple[str, str]:
        return self.name_edit.text().strip(), self.path_edit.text().strip()


class FortiVPNWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(build_status_icon())
        self.setMinimumWidth(385)

        self.state = "disconnected"  # disconnected | connecting | connected | disconnecting
        self.connected_since: float | None = None
        self._last_elapsed_secs: int = -1
        self.vpn_ip: str = ""
        self.vpn_iface: str = ""
        self.rx_bytes: int = 0
        self.tx_bytes: int = 0
        self._ip_copied_feedback: bool = False
        self.proc: QProcess | None = None
        self.stdout_buf = ""
        self.runner_ready = False
        self.pending_start_payload: dict | None = None
        self.last_error_line = ""
        self.detected_untrusted_digest = ""
        self.quitting = False
        self.tray_notified = False
        self.user_requested_disconnect = False
        self.session_pem_passphrases: dict[str, str] = {}

        self.profiles: list[dict] = []
        self.selected_profile_idx = 0
        self._load_settings()

        self._build_ui()
        self._build_tray()
        self._apply_styles()

        self.elapsed_timer = QTimer(self)
        self.elapsed_timer.setInterval(250)
        self.elapsed_timer.timeout.connect(self._update_elapsed)

        self._populate_profiles()
        self._update_ui_state()

        QTimer.singleShot(50, self._focus_initial_field)

    def _default_profiles(self) -> list[dict]:
        found = []
        for name, candidate in DEFAULT_CONF_CANDIDATES:
            if os.path.exists(candidate):
                found.append({"name": name, "path": candidate})
        if found:
            return found
        return [{"name": "Mi VPN", "path": ""}]

    def _load_settings(self):
        if SETTINGS_FILE.is_file():
            try:
                data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
                profs = data.get("profiles")
                if isinstance(profs, list) and profs:
                    cleaned = []
                    for p in profs:
                        if not isinstance(p, dict) or not p.get("path"):
                            continue
                        entry = {
                            "name": str(p.get("name", "VPN")),
                            "path": str(p.get("path", "")),
                        }
                        if isinstance(p.get("cert_overrides"), dict):
                            entry["cert_overrides"] = p["cert_overrides"]
                        cleaned.append(entry)
                    self.profiles = cleaned
                self.selected_profile_idx = int(data.get("selected", 0))
            except Exception:
                self.profiles = []
                self.selected_profile_idx = 0
        if not self.profiles:
            self.profiles = self._default_profiles()
            self.selected_profile_idx = 0
        self.selected_profile_idx = max(0, min(self.selected_profile_idx, len(self.profiles) - 1))

    def _save_settings(self):
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            data = {
                "profiles": self.profiles,
                "selected": self.profile_combo.currentIndex() if hasattr(self, "profile_combo") else 0,
            }
            SETTINGS_FILE.write_text(
                json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        except OSError:
            pass

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(14, 12, 14, 10)
        root.setSpacing(9)

        # Header
        header = QHBoxLayout()
        header.setSpacing(9)

        icon_lbl = QLabel()
        icon_lbl.setPixmap(build_status_icon().pixmap(QSize(28, 28)))
        header.addWidget(icon_lbl)

        title_col = QVBoxLayout()
        title_col.setSpacing(0)
        title_lbl = QLabel("FortiVPN")
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        title_lbl.setFont(title_font)

        self.subtitle_lbl = QLabel("Cliente OpenFortiVPN")
        self.subtitle_lbl.setObjectName("mutedLabel")
        title_col.addWidget(title_lbl)
        title_col.addWidget(self.subtitle_lbl)
        header.addLayout(title_col, 1)

        self.status_badge = StatusBadge(self)
        header.addWidget(self.status_badge)
        root.addLayout(header)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setObjectName("separator")
        root.addWidget(sep)

        # --- Disconnected / Connecting Form Panel ---
        self.connect_panel = QWidget()
        form = QFormLayout(self.connect_panel)
        form.setContentsMargins(0, 0, 0, 0)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(7)

        # Connection selector + buttons
        conn_col = QVBoxLayout()
        conn_col.setSpacing(5)
        conn_row = QHBoxLayout()
        conn_row.setSpacing(5)

        self.profile_combo = QComboBox()
        self.profile_combo.setMinimumHeight(30)
        self.profile_combo.currentIndexChanged.connect(self._on_profile_changed)
        conn_row.addWidget(self.profile_combo, 1)

        self.add_btn = QToolButton()
        self.add_btn.setText("+")
        self.add_btn.setToolTip("Añadir o crear conexión (.conf)")
        self.add_btn.setFixedSize(28, 30)
        self.add_btn.clicked.connect(self._add_profile)
        conn_row.addWidget(self.add_btn)

        self.edit_btn = QToolButton()
        self.edit_btn.setText("✎")
        self.edit_btn.setToolTip("Editar nombre o archivo .conf")
        self.edit_btn.setFixedSize(28, 30)
        self.edit_btn.clicked.connect(self._edit_profile)
        conn_row.addWidget(self.edit_btn)

        self.del_btn = QToolButton()
        self.del_btn.setText("✕")
        self.del_btn.setToolTip("Eliminar conexión de la lista")
        self.del_btn.setFixedSize(28, 30)
        self.del_btn.clicked.connect(self._delete_profile)
        conn_row.addWidget(self.del_btn)

        conn_col.addLayout(conn_row)

        # Compact server URL + Certificates icon button strip
        meta_bar = QFrame()
        meta_bar.setObjectName("metaBar")
        meta_row = QHBoxLayout(meta_bar)
        meta_row.setContentsMargins(8, 3, 4, 3)
        meta_row.setSpacing(6)

        self.url_icon_lbl = QLabel()
        self.url_icon_lbl.setPixmap(build_globe_pixmap(14, "#64748b"))
        self.url_icon_lbl.setFixedSize(14, 14)
        meta_row.addWidget(self.url_icon_lbl)

        self.conf_info_lbl = QLabel("")
        self.conf_info_lbl.setObjectName("confInfoLabel")
        self.conf_info_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        meta_row.addWidget(self.conf_info_lbl, 1)

        self.certs_btn = QToolButton()
        self.certs_btn.setObjectName("certIconBtn")
        self.certs_btn.setIcon(build_cert_icon(False))
        self.certs_btn.setIconSize(QSize(16, 16))
        self.certs_btn.setFixedSize(26, 26)
        self.certs_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.certs_btn.clicked.connect(self._on_certs_clicked)
        meta_row.addWidget(self.certs_btn)

        conn_col.addWidget(meta_bar)

        form.addRow("Conexión:", conn_col)

        # Username
        self.user_edit = QLineEdit()
        self.user_edit.setMinimumHeight(30)
        self.user_edit.setPlaceholderText("Usar usuario del archivo .conf")
        self.user_edit.setClearButtonEnabled(True)
        self.user_edit.returnPressed.connect(lambda: self.pass_edit.setFocus())
        form.addRow("Usuario:", self.user_edit)

        # Password
        pass_row = QHBoxLayout()
        pass_row.setSpacing(5)
        self.pass_edit = QLineEdit()
        self.pass_edit.setMinimumHeight(30)
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_edit.setPlaceholderText("Contraseña VPN")
        self.pass_edit.returnPressed.connect(self._on_pass_enter)
        pass_row.addWidget(self.pass_edit, 1)

        self.show_pass_btn = QToolButton()
        self.show_pass_btn.setText("👁")
        self.show_pass_btn.setCheckable(True)
        self.show_pass_btn.setToolTip("Mostrar / ocultar contraseña")
        self.show_pass_btn.setFixedSize(30, 30)
        self.show_pass_btn.toggled.connect(self._toggle_password_visibility)
        pass_row.addWidget(self.show_pass_btn)
        form.addRow("Contraseña:", pass_row)

        # Token
        self.token_edit = QLineEdit()
        self.token_edit.setMinimumHeight(32)
        self.token_edit.setPlaceholderText("Código token / 2FA (ej. 123456)")
        self.token_edit.setClearButtonEnabled(True)
        token_font = QFont("monospace")
        token_font.setPointSize(10)
        self.token_edit.setFont(token_font)
        self.token_edit.returnPressed.connect(self._on_action_clicked)
        form.addRow("Token:", self.token_edit)

        root.addWidget(self.connect_panel)

        # --- Compact Connected Summary Card ---
        self.connected_panel = QFrame()
        self.connected_panel.setObjectName("connectedCard")
        self.connected_panel.setVisible(False)
        card_layout = QVBoxLayout(self.connected_panel)
        card_layout.setContentsMargins(11, 8, 8, 9)
        card_layout.setSpacing(8)

        # Row 1: Server URL + Certificates icon
        card_url_row = QHBoxLayout()
        card_url_row.setContentsMargins(0, 0, 0, 0)
        card_url_row.setSpacing(7)

        self.conn_url_icon_lbl = QLabel()
        self.conn_url_icon_lbl.setPixmap(build_globe_pixmap(14, "#64748b"))
        self.conn_url_icon_lbl.setFixedSize(14, 14)
        card_url_row.addWidget(self.conn_url_icon_lbl)

        self.conn_url_lbl = QLabel("")
        self.conn_url_lbl.setObjectName("connectedUrlLabel")
        self.conn_url_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        card_url_row.addWidget(self.conn_url_lbl, 1)

        self.conn_certs_btn = QToolButton()
        self.conn_certs_btn.setObjectName("certIconBtn")
        self.conn_certs_btn.setIcon(build_cert_icon(False))
        self.conn_certs_btn.setIconSize(QSize(16, 16))
        self.conn_certs_btn.setFixedSize(26, 26)
        self.conn_certs_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.conn_certs_btn.clicked.connect(self._on_certs_clicked)
        card_url_row.addWidget(self.conn_certs_btn)

        card_layout.addLayout(card_url_row)

        # Inner horizontal hairline divider
        card_hdiv = QFrame()
        card_hdiv.setFrameShape(QFrame.Shape.HLine)
        card_hdiv.setObjectName("cardDivider")
        card_layout.addWidget(card_hdiv)

        # Row 2: Compact telemetry strip (IP VPN | ↓ Recibido | ↑ Enviado)
        stats_row = QHBoxLayout()
        stats_row.setContentsMargins(0, 0, 2, 0)
        stats_row.setSpacing(10)

        # Column 1: IP VPN (clickable to copy)
        ip_col = QVBoxLayout()
        ip_col.setSpacing(1)
        self.ip_caption_lbl = QLabel("IP VPN")
        self.ip_caption_lbl.setObjectName("statCaption")
        self.ip_value_btn = QPushButton("—")
        self.ip_value_btn.setObjectName("ipValueBtn")
        self.ip_value_btn.setFlat(True)
        self.ip_value_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.ip_value_btn.setToolTip("Clic para copiar la IP VPN")
        self.ip_value_btn.clicked.connect(self._copy_vpn_ip)
        ip_col.addWidget(self.ip_caption_lbl)
        ip_col.addWidget(self.ip_value_btn, 0, Qt.AlignmentFlag.AlignLeft)
        stats_row.addLayout(ip_col, 4)

        vdiv1 = QFrame()
        vdiv1.setFrameShape(QFrame.Shape.VLine)
        vdiv1.setObjectName("cardDivider")
        stats_row.addWidget(vdiv1)

        # Column 2: Received bytes
        rx_col = QVBoxLayout()
        rx_col.setSpacing(1)
        rx_cap = QLabel("↓ RECIBIDO")
        rx_cap.setObjectName("statCaptionRx")
        self.rx_value_lbl = QLabel("0 B")
        self.rx_value_lbl.setObjectName("statValue")
        rx_col.addWidget(rx_cap)
        rx_col.addWidget(self.rx_value_lbl)
        stats_row.addLayout(rx_col, 3)

        vdiv2 = QFrame()
        vdiv2.setFrameShape(QFrame.Shape.VLine)
        vdiv2.setObjectName("cardDivider")
        stats_row.addWidget(vdiv2)

        # Column 3: Sent bytes
        tx_col = QVBoxLayout()
        tx_col.setSpacing(1)
        tx_cap = QLabel("↑ ENVIADO")
        tx_cap.setObjectName("statCaptionTx")
        self.tx_value_lbl = QLabel("0 B")
        self.tx_value_lbl.setObjectName("statValue")
        tx_col.addWidget(tx_cap)
        tx_col.addWidget(self.tx_value_lbl)
        stats_row.addLayout(tx_col, 3)

        card_layout.addLayout(stats_row)
        root.addWidget(self.connected_panel)

        # Alert banner
        self.alert_lbl = QLabel("")
        self.alert_lbl.setObjectName("alertBanner")
        self.alert_lbl.setWordWrap(True)
        self.alert_lbl.setVisible(False)
        root.addWidget(self.alert_lbl)

        # Action button
        self.action_btn = QPushButton("Conectar")
        self.action_btn.setObjectName("primaryButton")
        self.action_btn.setMinimumHeight(36)
        self.action_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.action_btn.clicked.connect(self._on_action_clicked)
        root.addWidget(self.action_btn)

        # Compact log toggle bar
        log_bar = QHBoxLayout()
        log_bar.setContentsMargins(0, 0, 0, 0)
        self.log_toggle_btn = QPushButton("▸ Registro")
        self.log_toggle_btn.setObjectName("subtleLinkBtn")
        self.log_toggle_btn.setFlat(True)
        self.log_toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.log_toggle_btn.clicked.connect(self._toggle_log_drawer)
        log_bar.addWidget(self.log_toggle_btn)
        log_bar.addStretch(1)

        self.copy_log_btn = QPushButton("Copiar")
        self.copy_log_btn.setObjectName("subtleLinkBtn")
        self.copy_log_btn.setFlat(True)
        self.copy_log_btn.setVisible(False)
        self.copy_log_btn.clicked.connect(self._copy_log)
        log_bar.addWidget(self.copy_log_btn)

        self.clear_log_btn = QPushButton("Limpiar")
        self.clear_log_btn.setObjectName("subtleLinkBtn")
        self.clear_log_btn.setFlat(True)
        self.clear_log_btn.setVisible(False)
        self.clear_log_btn.clicked.connect(lambda: self.log_view.clear())
        log_bar.addWidget(self.clear_log_btn)
        root.addLayout(log_bar)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(1000)
        self.log_view.setMinimumHeight(135)
        self.log_view.setMaximumHeight(200)
        log_font = QFont("monospace")
        log_font.setPointSize(9)
        self.log_view.setFont(log_font)
        self.log_view.setVisible(False)
        root.addWidget(self.log_view)

    def _build_tray(self):
        self.tray = QSystemTrayIcon(build_status_icon("#64748b"), self)
        self.tray.setToolTip("FortiVPN — Desconectado")
        self.tray.activated.connect(self._on_tray_activated)

        menu = QMenu()
        self.tray_show_act = QAction("Mostrar ventana", self)
        self.tray_show_act.triggered.connect(self.bring_to_front)
        menu.addAction(self.tray_show_act)

        self.tray_toggle_act = QAction("Conectar", self)
        self.tray_toggle_act.triggered.connect(self._on_action_clicked)
        menu.addAction(self.tray_toggle_act)

        menu.addSeparator()

        quit_act = QAction("Salir", self)
        quit_act.triggered.connect(self._quit_app)
        menu.addAction(quit_act)

        self.tray.setContextMenu(menu)
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray.show()

    def _apply_styles(self):
        self.setStyleSheet(
            """
            #mutedLabel {
                font-size: 11px;
                color: #94a3b8;
            }
            #metaBar {
                background-color: rgba(148, 163, 184, 0.10);
                border: 1px solid rgba(148, 163, 184, 0.22);
                border-radius: 7px;
            }
            #connectedCard {
                background-color: rgba(148, 163, 184, 0.09);
                border: 1px solid rgba(148, 163, 184, 0.22);
                border-radius: 9px;
            }
            #cardDivider {
                color: rgba(148, 163, 184, 0.20);
            }
            #confInfoLabel, #connectedUrlLabel {
                font-size: 11.5px;
                font-family: monospace;
                color: #94a3b8;
            }
            #connectedUrlLabel {
                font-weight: 600;
            }
            #certIconBtn {
                border-radius: 6px;
                background-color: rgba(148, 163, 184, 0.12);
                border: 1px solid rgba(148, 163, 184, 0.24);
                padding: 2px;
            }
            #certIconBtn:hover {
                background-color: rgba(59, 130, 246, 0.18);
                border-color: rgba(59, 130, 246, 0.50);
            }
            #certIconBtn[configured="true"] {
                background-color: rgba(34, 197, 94, 0.14);
                border: 1px solid rgba(34, 197, 94, 0.40);
            }
            #certIconBtn[configured="true"]:hover {
                background-color: rgba(34, 197, 94, 0.24);
            }
            #statCaption {
                font-size: 9.5px;
                font-weight: 700;
                letter-spacing: 0.4px;
                color: #94a3b8;
            }
            #statCaptionRx {
                font-size: 9.5px;
                font-weight: 700;
                letter-spacing: 0.4px;
                color: #22c55e;
            }
            #statCaptionTx {
                font-size: 9.5px;
                font-weight: 700;
                letter-spacing: 0.4px;
                color: #3b82f6;
            }
            #statValue {
                font-size: 12.5px;
                font-weight: 700;
                font-family: monospace;
            }
            #ipValueBtn {
                font-size: 12.5px;
                font-weight: 700;
                font-family: monospace;
                padding: 0px;
                border: none;
                background: transparent;
                text-align: left;
            }
            #ipValueBtn:hover {
                color: #3b82f6;
            }
            #separator {
                color: rgba(148, 163, 184, 0.22);
            }
            #alertBanner {
                padding: 7px 9px;
                border-radius: 6px;
                font-size: 11.5px;
                background-color: rgba(239, 68, 68, 0.14);
                border: 1px solid rgba(239, 68, 68, 0.45);
                color: #ef4444;
            }
            #primaryButton {
                border-radius: 8px;
                font-size: 13.5px;
                font-weight: 700;
                color: #ffffff;
                border: none;
                padding: 6px 14px;
            }
            #subtleLinkBtn {
                font-size: 11px;
                color: #94a3b8;
                padding: 1px 4px;
                border: none;
                background: transparent;
            }
            #subtleLinkBtn:hover {
                color: #3b82f6;
            }
            """
        )

    def _focus_initial_field(self):
        if not self.user_edit.text().strip() and not self._current_conf_meta().get("username"):
            self.user_edit.setFocus()
        else:
            self.pass_edit.setFocus()

    def _populate_profiles(self):
        self.profile_combo.blockSignals(True)
        self.profile_combo.clear()
        for prof in self.profiles:
            self.profile_combo.addItem(prof["name"], prof["path"])
        idx = max(0, min(self.selected_profile_idx, len(self.profiles) - 1))
        self.profile_combo.setCurrentIndex(idx)
        self.profile_combo.blockSignals(False)
        self._on_profile_changed(idx)

    def _current_profile(self) -> dict:
        idx = self.profile_combo.currentIndex()
        if 0 <= idx < len(self.profiles):
            return self.profiles[idx]
        return {"name": "VPN", "path": ""}

    def _current_conf_meta(self) -> dict:
        return parse_openfortivpn_conf(self._current_profile().get("path", ""))

    def _cert_summary_details(self, prof: dict, meta: dict) -> list[str]:
        eff = effective_cert_settings(prof, meta)
        details = []
        if eff["ca-file"]:
            details.append(f"CA: {eff['ca-file']}")
        if eff["user-cert"]:
            details.append(f"Cert. usuario: {eff['user-cert']}")
        if eff["user-key"]:
            details.append(f"Clave privada: {eff['user-key']}")
        if eff["trusted-cert"]:
            n = len(eff["trusted-cert"])
            details.append(f"trusted-cert: {n} huella(s)")
        return details

    def _refresh_cert_summary(self, prof: dict, meta: dict):
        details = self._cert_summary_details(prof, meta)
        configured = bool(details)
        icon = build_cert_icon(configured)

        if configured:
            tip_edit = "Certificados activos:\n• " + "\n• ".join(details) + "\n\nClic para configurar"
            tip_view = "Certificados activos:\n• " + "\n• ".join(details) + "\n\nClic para ver detalles"
        else:
            tip_edit = (
                "Certificados (almacén del sistema)\n"
                "Clic para configurar CA, cert. usuario o trusted-cert."
            )
            tip_view = "Certificados: almacén del sistema\nClic para ver detalles"

        for btn, tip in ((self.certs_btn, tip_edit), (self.conn_certs_btn, tip_view)):
            btn.setIcon(icon)
            btn.setProperty("configured", "true" if configured else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)
            btn.setToolTip(tip)

    def _on_certs_clicked(self):
        if self.state == "disconnected":
            self._edit_certs()
            return
        prof = self._current_profile()
        path = prof.get("path", "")
        meta = parse_openfortivpn_conf(path)
        details = self._cert_summary_details(prof, meta)
        if details:
            body = "Certificados activos en esta conexión:\n\n• " + "\n• ".join(details)
        else:
            body = "Esta conexión utiliza el almacén de certificados del sistema (sin certificados personalizados)."
        body += "\n\nDesconecta la VPN para modificar la configuración de certificados."
        QMessageBox.information(self, "Certificados de la conexión", body)

    def _on_profile_changed(self, idx: int):
        if idx < 0 or idx >= len(self.profiles):
            return
        self.selected_profile_idx = idx
        self._save_settings()

        prof = self.profiles[idx]
        path = prof["path"]
        meta = parse_openfortivpn_conf(path)

        url_display = ""
        url_tooltip = path

        if not path:
            self.conf_info_lbl.setText("Pulsa '+' o '✎' para elegir o crear tu .conf")
            self.conf_info_lbl.setToolTip("")
            self.conf_info_lbl.setStyleSheet("font-size: 11px; color: #f59e0b;")
            self.url_icon_lbl.setPixmap(build_globe_pixmap(14, "#f59e0b"))
            self.user_edit.setPlaceholderText("Usuario VPN")
            self.pass_edit.setPlaceholderText("Contraseña VPN")
            url_display = prof.get("name", "VPN")
        elif not meta["exists"]:
            self.conf_info_lbl.setText("⚠ Archivo .conf no encontrado")
            self.conf_info_lbl.setToolTip(path)
            self.conf_info_lbl.setStyleSheet("font-size: 11px; color: #f59e0b;")
            self.url_icon_lbl.setPixmap(build_globe_pixmap(14, "#f59e0b"))
            self.user_edit.setPlaceholderText("Usuario VPN")
            self.pass_edit.setPlaceholderText("Contraseña VPN")
            url_display = Path(path).name
        elif not meta["readable"]:
            url_display = Path(path).name
            self.conf_info_lbl.setText(url_display)
            self.conf_info_lbl.setToolTip(f"{path}\n(Se leerá con permisos al conectar)")
            self.conf_info_lbl.setStyleSheet("font-size: 11.5px; font-family: monospace; color: #94a3b8;")
            self.url_icon_lbl.setPixmap(build_globe_pixmap(14, "#64748b"))
            self.user_edit.setPlaceholderText("Usar usuario del archivo .conf")
            self.pass_edit.setPlaceholderText("Contraseña VPN")
        else:
            if meta["host"]:
                url_display = f"{meta['host']}:{meta['port']}" if meta["port"] else meta["host"]
            else:
                url_display = Path(path).name
            self.conf_info_lbl.setText(url_display)
            self.conf_info_lbl.setToolTip(path)
            self.conf_info_lbl.setStyleSheet("font-size: 11.5px; font-family: monospace; color: #94a3b8;")
            self.url_icon_lbl.setPixmap(build_globe_pixmap(14, "#64748b"))

            if meta["username"]:
                self.user_edit.setText(meta["username"])
            else:
                self.user_edit.clear()

            if meta["has_password"]:
                self.pass_edit.setPlaceholderText("Definida en .conf (escribe aquí para reemplazar)")
            else:
                self.pass_edit.setPlaceholderText("Contraseña VPN")

        self.conn_url_lbl.setText(url_display)
        self.conn_url_lbl.setToolTip(f"{url_display}\n{url_tooltip}" if url_tooltip else url_display)
        self.conn_url_icon_lbl.setPixmap(build_globe_pixmap(14, "#64748b"))

        self._refresh_cert_summary(prof, meta)
        self.del_btn.setEnabled(len(self.profiles) > 1 and self.state == "disconnected")

    def _edit_certs(self):
        idx = self.profile_combo.currentIndex()
        if idx < 0 or idx >= len(self.profiles):
            return
        prof = self.profiles[idx]
        path = prof["path"]
        meta = parse_openfortivpn_conf(path)
        current = effective_cert_settings(prof, meta)
        cur_pem_pass = self.session_pem_passphrases.get(path, "")

        dlg = CertsDialog(self, path, meta, current, cur_pem_pass)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        new_certs, pem_pass, save_to_conf = dlg.result_values()
        if pem_pass:
            self.session_pem_passphrases[path] = pem_pass
        else:
            self.session_pem_passphrases.pop(path, None)

        saved_to_file = False
        if save_to_conf and meta.get("exists") and meta.get("writable"):
            try:
                update_openfortivpn_conf(path, new_certs)
                saved_to_file = True
                # Clear profile override since .conf itself now has the canonical values
                prof.pop("cert_overrides", None)
            except OSError as exc:
                QMessageBox.warning(
                    self,
                    "No se pudo escribir en el .conf",
                    f"Se guardará solo en el perfil de la app.\nDetalle: {exc}",
                )

        if not saved_to_file:
            prof["cert_overrides"] = new_certs

        self._save_settings()
        self._on_profile_changed(idx)

    def _trust_and_save_digest(self, digest: str) -> bool:
        """Persist a newly trusted server SHA-256 digest to .conf (or profile override)."""
        idx = self.profile_combo.currentIndex()
        if idx < 0 or idx >= len(self.profiles):
            return False
        prof = self.profiles[idx]
        path = prof["path"]
        meta = parse_openfortivpn_conf(path)
        eff = effective_cert_settings(prof, meta)

        if digest not in eff["trusted-cert"]:
            eff["trusted-cert"].append(digest)

        saved_to_file = False
        if meta.get("exists") and meta.get("writable"):
            try:
                update_openfortivpn_conf(path, {"trusted-cert": eff["trusted-cert"]})
                saved_to_file = True
                if isinstance(prof.get("cert_overrides"), dict):
                    prof["cert_overrides"].pop("trusted-cert", None)
                    if not prof["cert_overrides"]:
                        prof.pop("cert_overrides", None)
            except OSError:
                saved_to_file = False

        if not saved_to_file:
            overrides = prof.setdefault("cert_overrides", {})
            overrides["trusted-cert"] = eff["trusted-cert"]

        self._save_settings()
        self._refresh_cert_summary(prof, parse_openfortivpn_conf(path))
        return True

    def _add_profile(self):
        dlg = ProfileDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            name, path = dlg.values()
            self.profiles.append({"name": name, "path": path})
            self.selected_profile_idx = len(self.profiles) - 1
            self._populate_profiles()
            self._save_settings()

    def _edit_profile(self):
        idx = self.profile_combo.currentIndex()
        if idx < 0 or idx >= len(self.profiles):
            return
        prof = self.profiles[idx]
        dlg = ProfileDialog(self, prof["name"], prof["path"])
        if dlg.exec() == QDialog.DialogCode.Accepted:
            name, path = dlg.values()
            entry = {"name": name, "path": path}
            if path == prof["path"] and isinstance(prof.get("cert_overrides"), dict):
                entry["cert_overrides"] = prof["cert_overrides"]
            self.profiles[idx] = entry
            self.selected_profile_idx = idx
            self._populate_profiles()
            self._save_settings()

    def _delete_profile(self):
        if len(self.profiles) <= 1:
            return
        idx = self.profile_combo.currentIndex()
        prof = self.profiles[idx]
        res = QMessageBox.question(
            self,
            "Eliminar conexión",
            f"¿Quitar '{prof['name']}' de la lista?\n(No se borrará el archivo .conf del disco)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if res == QMessageBox.StandardButton.Yes:
            self.profiles.pop(idx)
            self.selected_profile_idx = max(0, idx - 1)
            self._populate_profiles()
            self._save_settings()

    def _toggle_password_visibility(self, checked: bool):
        self.pass_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        )

    def _on_pass_enter(self):
        if self.token_edit.text().strip():
            self._on_action_clicked()
        else:
            self.token_edit.setFocus()

    def _fit_window_size(self):
        if self.centralWidget() and self.centralWidget().layout():
            self.centralWidget().layout().activate()
        hint = self.sizeHint()
        target_w = max(self.minimumWidth(), hint.width())
        self.resize(target_w, hint.height())

    def _copy_vpn_ip(self):
        if not self.vpn_ip:
            return
        QApplication.clipboard().setText(self.vpn_ip)
        self._ip_copied_feedback = True
        self.ip_value_btn.setText("✓ Copiada")
        QTimer.singleShot(1200, self._restore_ip_label)

    def _restore_ip_label(self):
        self._ip_copied_feedback = False
        self.ip_value_btn.setText(self.vpn_ip or "—")

    def _update_connected_telemetry(self):
        if not self.vpn_iface:
            self.vpn_iface = detect_vpn_iface(self.vpn_ip)
        if self.vpn_iface and not self.vpn_ip:
            detected_ip = get_iface_ipv4(self.vpn_iface)
            if detected_ip:
                self.vpn_ip = detected_ip

        self.ip_caption_lbl.setText(f"IP · {self.vpn_iface}" if self.vpn_iface else "IP VPN")
        if not self._ip_copied_feedback:
            self.ip_value_btn.setText(self.vpn_ip or "—")

        stats = read_iface_bytes(self.vpn_iface) if self.vpn_iface else None
        if stats is not None:
            self.rx_bytes, self.tx_bytes = stats
        self.rx_value_lbl.setText(format_bytes(self.rx_bytes))
        self.tx_value_lbl.setText(format_bytes(self.tx_bytes))

    def _toggle_log_drawer(self):
        visible = not self.log_view.isVisible()
        self.log_view.setVisible(visible)
        self.copy_log_btn.setVisible(visible)
        self.clear_log_btn.setVisible(visible)
        self.log_toggle_btn.setText("▾ Ocultar registro" if visible else "▸ Registro")
        QTimer.singleShot(0, self._fit_window_size)

    def _copy_log(self):
        QApplication.clipboard().setText(self.log_view.toPlainText())

    def _append_log(self, text: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_view.appendPlainText(f"[{ts}] {text}")
        sb = self.log_view.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _show_alert(self, message: str):
        if message:
            self.alert_lbl.setText(message)
            self.alert_lbl.setVisible(True)
        else:
            self.alert_lbl.clear()
            self.alert_lbl.setVisible(False)
        QTimer.singleShot(0, self._fit_window_size)

    def _format_elapsed(self, secs: int) -> str:
        secs = max(0, secs)
        h, rem = divmod(secs, 3600)
        m, s = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"

    def _set_state(self, new_state: str, detail: str = ""):
        self.state = new_state
        if new_state == "connected":
            self.connected_since = time.monotonic()
            self._last_elapsed_secs = -1
            self.rx_bytes = 0
            self.tx_bytes = 0
            self.token_edit.clear()
            self.elapsed_timer.start()
            self._show_alert("")
            self._update_connected_telemetry()
        elif new_state == "disconnected":
            self.connected_since = None
            self._last_elapsed_secs = -1
            self.vpn_ip = ""
            self.vpn_iface = ""
            self.rx_bytes = 0
            self.tx_bytes = 0
            self._ip_copied_feedback = False
            self.elapsed_timer.stop()
            # Only clear token if we actually connected or user disconnected
            if self.user_requested_disconnect or not self.detected_untrusted_digest:
                self.token_edit.clear()
        self._update_ui_state(detail)

    def _update_elapsed(self):
        if self.state == "connected" and self.connected_since is not None:
            secs = int(time.monotonic() - self.connected_since)
            if secs == self._last_elapsed_secs:
                return
            self._last_elapsed_secs = secs
            elapsed = self._format_elapsed(secs)
            self.status_badge.set_elapsed(elapsed)
            self._update_connected_telemetry()
            prof_name = self._current_profile()["name"]
            ip_part = f" ({self.vpn_ip})" if self.vpn_ip else ""
            traffic = f" · ↓ {format_bytes(self.rx_bytes)} ↑ {format_bytes(self.tx_bytes)}"
            self.tray.setToolTip(f"FortiVPN — Conectado a {prof_name}{ip_part} · {elapsed}{traffic}")

    def _update_ui_state(self, detail: str = ""):
        idle = self.state == "disconnected"
        compact_connected = self.state in ("connected", "disconnecting")

        self.connect_panel.setVisible(not compact_connected)
        self.connected_panel.setVisible(compact_connected)

        self.profile_combo.setEnabled(idle)
        self.add_btn.setEnabled(idle)
        self.edit_btn.setEnabled(idle)
        self.del_btn.setEnabled(idle and len(self.profiles) > 1)
        self.certs_btn.setEnabled(idle)
        self.user_edit.setEnabled(idle)
        self.pass_edit.setEnabled(idle)
        self.token_edit.setEnabled(idle)
        if not compact_connected:
            self.token_edit.setPlaceholderText("Código token / 2FA (ej. 123456)")

        prof_name = self._current_profile()["name"]

        if self.state == "disconnected":
            self.status_badge.set_status("disconnected")
            self.subtitle_lbl.setText("Cliente OpenFortiVPN")
            self.action_btn.setText("Conectar")
            self.action_btn.setEnabled(True)
            self.action_btn.setStyleSheet(
                "QPushButton { background-color: #2563eb; color: #ffffff; border-radius: 8px;"
                " font-size: 13.5px; font-weight: 700; border: none; }"
                "QPushButton:hover { background-color: #1d4ed8; }"
                "QPushButton:pressed { background-color: #1e40af; }"
            )
            self.tray.setIcon(build_status_icon("#64748b"))
            self.tray.setToolTip("FortiVPN — Desconectado")
            self.tray_toggle_act.setText("Conectar")
            self.tray_toggle_act.setEnabled(True)

        elif self.state == "connecting":
            self.status_badge.set_status("connecting")
            self.subtitle_lbl.setText(detail or "Esperando autorización y conexión...")
            self.action_btn.setText("Cancelar")
            self.action_btn.setEnabled(True)
            self.action_btn.setStyleSheet(
                "QPushButton { background-color: #d97706; color: #ffffff; border-radius: 8px;"
                " font-size: 13.5px; font-weight: 700; border: none; }"
                "QPushButton:hover { background-color: #b45309; }"
            )
            self.tray.setIcon(build_status_icon("#f59e0b"))
            self.tray.setToolTip(f"FortiVPN — Conectando a {prof_name}...")
            self.tray_toggle_act.setText("Cancelar conexión")
            self.tray_toggle_act.setEnabled(True)

        elif self.state == "connected":
            secs = int(time.monotonic() - self.connected_since) if self.connected_since is not None else 0
            elapsed = self._format_elapsed(secs)
            self._last_elapsed_secs = secs
            self.status_badge.set_status("connected", elapsed)
            self.subtitle_lbl.setText(prof_name)
            self._update_connected_telemetry()
            self.action_btn.setText("Desconectar")
            self.action_btn.setEnabled(True)
            self.action_btn.setStyleSheet(
                "QPushButton { background-color: #dc2626; color: #ffffff; border-radius: 8px;"
                " font-size: 13.5px; font-weight: 700; border: none; }"
                "QPushButton:hover { background-color: #b91c1c; }"
                "QPushButton:pressed { background-color: #991b1b; }"
            )
            self.tray.setIcon(build_status_icon("#22c55e"))
            ip_part = f" ({self.vpn_ip})" if self.vpn_ip else ""
            traffic = f" · ↓ {format_bytes(self.rx_bytes)} ↑ {format_bytes(self.tx_bytes)}"
            self.tray.setToolTip(f"FortiVPN — Conectado a {prof_name}{ip_part} · {elapsed}{traffic}")
            self.tray_toggle_act.setText("Desconectar")
            self.tray_toggle_act.setEnabled(True)

        elif self.state == "disconnecting":
            self.status_badge.set_status("disconnecting")
            self.subtitle_lbl.setText("Cerrando túnel VPN...")
            self.action_btn.setText("Desconectando...")
            self.action_btn.setEnabled(False)
            self.tray_toggle_act.setEnabled(False)

        QTimer.singleShot(0, self._fit_window_size)

    def _on_action_clicked(self):
        if self.state == "disconnected":
            self._start_vpn()
        elif self.state in ("connecting", "connected"):
            self._stop_vpn()

    def _start_vpn(self):
        prof = self._current_profile()
        config_path = prof.get("path", "").strip()
        if not config_path:
            self._show_alert("Selecciona un archivo .conf de OpenFortiVPN.")
            return

        if not RUNNER_PATH.is_file():
            self._show_alert(f"Falta el componente auxiliar: {RUNNER_PATH}")
            return

        self._show_alert("")
        self.last_error_line = ""
        self.detected_untrusted_digest = ""
        self.stdout_buf = ""
        self.runner_ready = False
        self.user_requested_disconnect = False

        username = self.user_edit.text().strip()
        password = self.pass_edit.text()
        otp = self.token_edit.text().strip()
        pem_passphrase = self.session_pem_passphrases.get(config_path, "")
        cert_overrides = prof.get("cert_overrides") if isinstance(prof.get("cert_overrides"), dict) else None

        self.pending_start_payload = {
            "cmd": "start",
            "config_path": config_path,
            "username": username,
            "password": password,
            "otp": otp,
            "pem_passphrase": pem_passphrase,
            "cert_overrides": cert_overrides,
        }

        self._set_state("connecting", "Solicitando permisos de administrador...")
        self._append_log(f"Conectando a '{prof['name']}' ({config_path})...")

        self.proc = QProcess(self)
        self.proc.setProcessChannelMode(QProcess.ProcessChannelMode.SeparateChannels)
        self.proc.readyReadStandardOutput.connect(self._on_proc_stdout)
        self.proc.readyReadStandardError.connect(self._on_proc_stderr)
        self.proc.finished.connect(self._on_proc_finished)
        self.proc.errorOccurred.connect(self._on_proc_error)

        pkexec_bin = shutil.which("pkexec") or "/usr/bin/pkexec"
        if not os.path.isfile(pkexec_bin):
            self._show_alert("No se encontró 'pkexec' (polkit) en el sistema.")
            self._set_state("disconnected")
            return

        py_bin = sys.executable if (sys.executable and os.path.isfile(sys.executable)) else "/usr/bin/python3"
        self.proc.start(pkexec_bin, [py_bin, str(RUNNER_PATH)])

    def _send_runner_cmd(self, payload: dict):
        if self.proc and self.proc.state() == QProcess.ProcessState.Running:
            data = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
            self.proc.write(data)

    def _stop_vpn(self):
        if not self.proc or self.proc.state() == QProcess.ProcessState.NotRunning:
            self._set_state("disconnected")
            return

        self.user_requested_disconnect = True
        self._set_state("disconnecting")
        if self.runner_ready:
            self._send_runner_cmd({"cmd": "disconnect"})
            self.proc.closeWriteChannel()
        else:
            self.proc.terminate()

    def _on_proc_stdout(self):
        if not self.proc:
            return
        raw = bytes(self.proc.readAllStandardOutput()).decode("utf-8", errors="replace")
        self.stdout_buf += raw
        while "\n" in self.stdout_buf:
            line, self.stdout_buf = self.stdout_buf.split("\n", 1)
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                self._append_log(line)
                continue
            self._handle_runner_msg(msg)

    def _on_proc_stderr(self):
        if not self.proc:
            return
        raw = bytes(self.proc.readAllStandardError()).decode("utf-8", errors="replace").strip()
        if raw:
            self._append_log(f"[stderr] {raw}")

    def _handle_runner_msg(self, msg: dict):
        mtype = msg.get("type")

        if mtype == "ready":
            self.runner_ready = True
            self.subtitle_lbl.setText("Conectando con el servidor VPN...")
            if self.pending_start_payload:
                self._send_runner_cmd(self.pending_start_payload)
                self.pending_start_payload = None

        elif mtype == "log":
            line = str(msg.get("line", ""))
            self._append_log(line)
            if "ERROR:" in line or "error:" in line.lower():
                self.last_error_line = line

        elif mtype == "untrusted_cert":
            digest = str(msg.get("digest", "")).strip().lower()
            if digest:
                self.detected_untrusted_digest = digest

        elif mtype == "state":
            st = str(msg.get("state", "disconnected"))
            self._set_state(st)
            if st == "connected" and QSystemTrayIcon.isSystemTrayAvailable():
                prof_name = self._current_profile()["name"]
                self.tray.showMessage(
                    APP_NAME,
                    f"Conectado a {prof_name}",
                    QSystemTrayIcon.MessageIcon.Information,
                    3000,
                )

        elif mtype == "status_detail":
            detail = str(msg.get("detail", ""))
            if detail and self.state != "disconnected":
                self.subtitle_lbl.setText(detail)

        elif mtype == "ip":
            self.vpn_ip = str(msg.get("ip", ""))
            if self.state == "connected":
                self._update_connected_telemetry()
                prof_name = self._current_profile()["name"]
                secs = int(time.monotonic() - self.connected_since) if self.connected_since is not None else 0
                elapsed = self._format_elapsed(secs)
                ip_part = f" ({self.vpn_ip})" if self.vpn_ip else ""
                traffic = f" · ↓ {format_bytes(self.rx_bytes)} ↑ {format_bytes(self.tx_bytes)}"
                self.tray.setToolTip(f"FortiVPN — Conectado a {prof_name}{ip_part} · {elapsed}{traffic}")

        elif mtype == "iface":
            iface = str(msg.get("iface", "")).strip()
            if iface:
                self.vpn_iface = iface
                if self.state == "connected":
                    self._update_connected_telemetry()

        elif mtype == "prompt":
            prompt_text = str(msg.get("text", "Introduce el valor solicitado:"))
            is_secret = bool(msg.get("secret", False))
            self._handle_interactive_prompt(prompt_text, is_secret)

        elif mtype == "error":
            err = str(msg.get("message", "Error desconocido"))
            self.last_error_line = err
            self._append_log(f"ERROR: {err}")
            self._show_alert(err)

    def _handle_interactive_prompt(self, prompt_text: str, is_secret: bool):
        self.bring_to_front()
        echo = QLineEdit.EchoMode.Password if is_secret else QLineEdit.EchoMode.Normal
        text, ok = QInputDialog.getText(
            self,
            "Autenticación VPN",
            prompt_text,
            echo,
        )
        if ok:
            self._send_runner_cmd({"cmd": "input", "text": text})
        else:
            self._stop_vpn()

    def _prompt_trust_certificate(self, digest: str):
        self.bring_to_front()
        prof = self._current_profile()
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Certificado del servidor no verificado")
        box.setText(
            f"El servidor de '{prof['name']}' ha presentado un certificado que no está en la lista de confianza."
        )
        box.setInformativeText(
            f"Huella SHA-256 (trusted-cert):\n{digest}\n\n"
            "¿Quieres confiar en este certificado, guardarlo en la configuración y volver a conectar?"
        )
        trust_btn = box.addButton("Confiar y reconectar", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Cancelar", QMessageBox.ButtonRole.RejectRole)
        box.exec()

        if box.clickedButton() == trust_btn:
            if self._trust_and_save_digest(digest):
                self._show_alert("")
                QTimer.singleShot(100, self._start_vpn)

    def _friendly_error(self, exit_code: int) -> str:
        if not self.runner_ready:
            if exit_code == 126:
                return "Autenticación de administrador cancelada."
            if exit_code == 127:
                return "No se pudo autorizar pkexec para iniciar openfortivpn."

        low = self.last_error_line.lower()
        if "could not authenticate" in low or "authentication failed" in low or "invalid" in low:
            return "Error de autenticación: revisa el usuario, contraseña o token."
        if "trusted-cert" in low or "certificate validation failed" in low:
            return "Certificado del servidor no verificado (pulsa el icono de escudo para añadir trusted-cert)."
        if "could not connect" in low or "resolve" in low or "timed out" in low:
            return "No se pudo conectar al servidor VPN. Comprueba tu conexión a internet."
        if self.last_error_line:
            return self.last_error_line
        if exit_code != 0:
            return f"La conexión finalizó con error (código {exit_code}). Abre el registro para más detalles."
        return ""

    def _on_proc_finished(self, exit_code: int, _exit_status):
        self.pending_start_payload = None
        was_connected = self.state == "connected"
        untrusted_digest = self.detected_untrusted_digest
        self._set_state("disconnected")
        self.proc = None

        if self.quitting:
            QApplication.quit()
            return

        if not self.user_requested_disconnect:
            if untrusted_digest:
                self.detected_untrusted_digest = ""
                self._prompt_trust_certificate(untrusted_digest)
                self.user_requested_disconnect = False
                return

            err_msg = self._friendly_error(exit_code)
            if err_msg:
                self._show_alert(err_msg)
                if not self.log_view.isVisible() and self.runner_ready:
                    self._toggle_log_drawer()
            elif was_connected:
                self._show_alert("La conexión VPN se ha cerrado.")

        self.detected_untrusted_digest = ""
        self.user_requested_disconnect = False

    def _on_proc_error(self, error):
        self._append_log(f"Error de proceso Qt: {error}")
        if self.state != "disconnected":
            self._set_state("disconnected")
            self._show_alert("No se pudo iniciar pkexec / openfortivpn.")

    def _on_tray_activated(self, reason):
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            if self.isVisible() and not self.isMinimized():
                self.hide()
            else:
                self.bring_to_front()

    def bring_to_front(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, event):
        if self.quitting:
            event.accept()
            return

        if self.state in ("connecting", "connected") and QSystemTrayIcon.isSystemTrayAvailable():
            event.ignore()
            self.hide()
            if not self.tray_notified:
                self.tray_notified = True
                self.tray.showMessage(
                    APP_NAME,
                    "La VPN sigue activa en la bandeja del sistema.",
                    QSystemTrayIcon.MessageIcon.Information,
                    3000,
                )
        else:
            event.accept()
            QApplication.quit()

    def _quit_app(self):
        self.quitting = True
        if self.proc and self.proc.state() == QProcess.ProcessState.Running:
            self._stop_vpn()
            QTimer.singleShot(6000, QApplication.quit)
        else:
            QApplication.quit()


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setDesktopFileName("fortivpn-gui")
    app.setQuitOnLastWindowClosed(False)

    probe = QLocalSocket()
    probe.connectToServer(IPC_SERVER_NAME)
    if probe.waitForConnected(250):
        probe.write(b"show\n")
        probe.flush()
        probe.waitForBytesWritten(250)
        probe.disconnectFromServer()
        return 0

    QLocalServer.removeServer(IPC_SERVER_NAME)
    ipc_server = QLocalServer()
    ipc_server.listen(IPC_SERVER_NAME)

    win = FortiVPNWindow()

    def on_new_ipc():
        sock = ipc_server.nextPendingConnection()
        if sock:
            sock.waitForReadyRead(100)
            sock.close()
        win.bring_to_front()

    ipc_server.newConnection.connect(on_new_ipc)

    win.show()
    rc = app.exec()
    ipc_server.close()
    return rc


if __name__ == "__main__":
    sys.exit(main())
