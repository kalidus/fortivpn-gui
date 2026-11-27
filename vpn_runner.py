#!/usr/bin/env python3
"""Privileged OpenFortiVPN runner invoked via pkexec by fortivpn_gui.py.

Protocol (JSON lines):
  runner -> GUI (stdout):
    {"type": "ready"}
    {"type": "state", "state": "connecting" | "connected" | "disconnecting" | "disconnected"}
    {"type": "status_detail", "detail": "..."}
    {"type": "ip", "ip": "x.x.x.x"}
    {"type": "iface", "iface": "ppp0"}
    {"type": "untrusted_cert", "digest": "<sha256>"}
    {"type": "log", "line": "..."}
    {"type": "prompt", "text": "...", "secret": true|false}
    {"type": "error", "message": "..."}
    {"type": "exit", "code": 0}

  GUI -> runner (stdin):
    First line:
      {
        "cmd": "start",
        "config_path": "...",
        "username": "...",
        "password": "...",
        "otp": "...",
        "pem_passphrase": "...",
        "cert_overrides": {
          "ca-file": "...",
          "user-cert": "...",
          "user-key": "...",
          "trusted-cert": ["sha256...", ...]
        }
      }
    Subsequent lines:
      {"cmd": "input", "text": "..."}
      {"cmd": "disconnect"}
"""

import errno
import json
import os
import pty
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def find_openfortivpn() -> str | None:
    found = shutil.which("openfortivpn")
    if found and os.path.isfile(found):
        return found
    for candidate in (
        "/usr/bin/openfortivpn",
        "/usr/sbin/openfortivpn",
        "/usr/local/bin/openfortivpn",
        "/usr/local/sbin/openfortivpn",
    ):
        if os.path.isfile(candidate):
            return candidate
    return None

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07")
IP_ADDR_RE = re.compile(
    r"(?:Got addresses:\s*\[([0-9.]+)\]|local\s+IP address\s+([0-9.]+))",
    re.IGNORECASE,
)
IFACE_RE = re.compile(
    r"(?:Interface\s+([a-zA-Z0-9_.-]+)\s+is\s+UP|Using\s+interface\s+([a-zA-Z0-9_.-]+)|Connect:\s+([a-zA-Z0-9_.-]+)\s+<-->)",
    re.IGNORECASE,
)
TRUSTED_CERT_RE = re.compile(
    r"(?:--trusted-cert\s+|trusted-cert\s*=\s*)([0-9a-fA-F]{64})",
    re.IGNORECASE,
)
PROMPT_RE = re.compile(
    r"(password|passphrase|token|otp|passcode|two-factor|2fa|verification|pin|username)[^:\n]*:\s*$",
    re.IGNORECASE,
)
SECRET_PROMPT_RE = re.compile(r"(password|passphrase|pin)", re.IGNORECASE)


def emit(payload: dict) -> None:
    try:
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stdout.flush()
    except BrokenPipeError:
        pass


def sanitize_single_line(value: str) -> str:
    return value.replace("\r", "").replace("\n", "")


def build_temp_config(
    base_config_path: str,
    username: str = "",
    password: str = "",
    otp: str = "",
    pem_passphrase: str = "",
    cert_overrides: dict | None = None,
) -> str:
    if not base_config_path or not os.path.isfile(base_config_path):
        raise FileNotFoundError(
            f"No se encontró el archivo de configuración: {base_config_path}"
        )

    with open(base_config_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    single_overrides: dict[str, str | None] = {}
    if username:
        single_overrides["username"] = sanitize_single_line(username)
    if password:
        single_overrides["password"] = sanitize_single_line(password)
    if otp:
        single_overrides["otp"] = sanitize_single_line(otp)
    if pem_passphrase:
        single_overrides["pem-passphrase"] = sanitize_single_line(pem_passphrase)

    trusted_certs_override: list[str] | None = None
    if isinstance(cert_overrides, dict):
        for key in ("ca-file", "user-cert", "user-key"):
            if key in cert_overrides:
                val = sanitize_single_line(str(cert_overrides[key] or "")).strip()
                # None means remove the key if present; non-empty string replaces it
                single_overrides[key] = val if val else None
        if "trusted-cert" in cert_overrides:
            raw_list = cert_overrides["trusted-cert"]
            if isinstance(raw_list, list):
                trusted_certs_override = [
                    sanitize_single_line(str(c)).strip()
                    for c in raw_list
                    if str(c).strip()
                ]

    keys_to_strip = set(single_overrides.keys())
    if trusted_certs_override is not None:
        keys_to_strip.add("trusted-cert")

    out_lines = []
    for raw_line in lines:
        stripped = raw_line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip().lower()
            if key in keys_to_strip:
                continue
        out_lines.append(raw_line)

    if out_lines and not out_lines[-1].endswith("\n"):
        out_lines.append("\n")

    for key, val in single_overrides.items():
        if val:
            out_lines.append(f"{key} = {val}\n")

    if trusted_certs_override is not None:
        for digest in trusted_certs_override:
            out_lines.append(f"trusted-cert = {digest}\n")

    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        prefix="fortivpn_",
        suffix=".conf",
        dir="/tmp",
        delete=False,
        encoding="utf-8",
    )
    try:
        os.chmod(tmp.name, 0o600)
        tmp.writelines(out_lines)
        tmp.flush()
    finally:
        tmp.close()

    return tmp.name


def safe_unlink(path: str | None) -> None:
    if not path:
        return
    try:
        if os.path.exists(path):
            os.unlink(path)
    except OSError:
        pass


def terminate_proc(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGINT)
    except ProcessLookupError:
        return
    except OSError:
        try:
            proc.send_signal(signal.SIGINT)
        except OSError:
            pass

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(0.1)

    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except OSError:
        pass

    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(0.1)

    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass


def main() -> int:
    openfortivpn_bin = find_openfortivpn()
    if not openfortivpn_bin:
        emit({"type": "error", "message": "No se encontró el binario 'openfortivpn' en el sistema."})
        return 1

    # Tell GUI we are elevated and ready to receive credentials on stdin
    emit({"type": "ready"})

    start_line = sys.stdin.readline()
    if not start_line:
        return 0

    try:
        req = json.loads(start_line)
    except json.JSONDecodeError as exc:
        emit({"type": "error", "message": f"Error interno al leer configuración: {exc}"})
        return 1

    if req.get("cmd") != "start":
        emit({"type": "error", "message": "Comando inicial inválido."})
        return 1

    config_path = str(req.get("config_path") or "").strip()
    username = str(req.get("username") or "").strip()
    password = str(req.get("password") or "")
    otp = str(req.get("otp") or "").strip()
    pem_passphrase = str(req.get("pem_passphrase") or "")
    cert_overrides = req.get("cert_overrides")
    if not isinstance(cert_overrides, dict):
        cert_overrides = None

    secrets_to_redact = [s for s in (password, otp, pem_passphrase) if len(s) >= 3]

    def redact(text: str) -> str:
        res = text
        for secret in secrets_to_redact:
            res = res.replace(secret, "••••••")
        return res

    tmp_config = None
    master_fd = None
    proc = None
    shutting_down = False

    def handle_signal(_signum, _frame):
        nonlocal shutting_down
        shutting_down = True
        if proc is not None:
            terminate_proc(proc)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    try:
        tmp_config = build_temp_config(
            config_path,
            username=username,
            password=password,
            otp=otp,
            pem_passphrase=pem_passphrase,
            cert_overrides=cert_overrides,
        )
    except Exception as exc:
        emit({"type": "error", "message": str(exc)})
        return 1

    try:
        master_fd, slave_fd = pty.openpty()
        cwd = os.path.dirname(os.path.abspath(config_path))
        if not os.path.isdir(cwd):
            cwd = None

        emit({"type": "state", "state": "connecting"})
        emit({"type": "log", "line": f"Iniciando openfortivpn con {config_path}..."})

        proc = subprocess.Popen(
            [openfortivpn_bin, "-c", tmp_config],
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            cwd=cwd,
            start_new_session=True,
            close_fds=True,
        )
        os.close(slave_fd)

        os.set_blocking(master_fd, False)
        stdin_fd = sys.stdin.fileno()
        os.set_blocking(stdin_fd, False)

        sel = selectors.DefaultSelector()
        sel.register(master_fd, selectors.EVENT_READ, data="pty")
        sel.register(stdin_fd, selectors.EVENT_READ, data="stdin")

        pty_buf = ""
        stdin_buf = ""
        last_pty_data = 0.0
        last_prompt_sent = ""
        pty_open = True
        config_cleaned = False
        reported_untrusted = set()

        def process_line(raw_line: str) -> None:
            nonlocal config_cleaned
            clean = ANSI_RE.sub("", raw_line).rstrip("\r\n")
            if not clean.strip():
                return

            emit({"type": "log", "line": redact(clean)})

            lower = clean.lower()
            if "authenticated." in lower:
                emit({"type": "status_detail", "detail": "Autenticado, levantando túnel..."})
                if not config_cleaned:
                    safe_unlink(tmp_config)
                    config_cleaned = True
            elif "tunnel is up and running" in lower:
                emit({"type": "state", "state": "connected"})
                if not config_cleaned:
                    safe_unlink(tmp_config)
                    config_cleaned = True
            elif "logged out" in lower or "terminated" in lower:
                emit({"type": "status_detail", "detail": "Cerrando sesión VPN..."})

            ip_match = IP_ADDR_RE.search(clean)
            if ip_match:
                ip = ip_match.group(1) or ip_match.group(2)
                if ip:
                    emit({"type": "ip", "ip": ip})

            iface_match = IFACE_RE.search(clean)
            if iface_match:
                iface = iface_match.group(1) or iface_match.group(2) or iface_match.group(3)
                if iface:
                    emit({"type": "iface", "iface": iface})

            cert_match = TRUSTED_CERT_RE.search(clean)
            if cert_match:
                digest = cert_match.group(1).lower()
                if digest not in reported_untrusted:
                    reported_untrusted.add(digest)
                    emit({"type": "untrusted_cert", "digest": digest})

        while True:
            if shutting_down:
                break

            events = sel.select(timeout=0.2)
            for key, _ in events:
                if key.data == "pty":
                    try:
                        chunk = os.read(master_fd, 4096)
                    except OSError as exc:
                        if exc.errno in (errno.EIO, errno.EBADF):
                            chunk = b""
                        elif exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                            continue
                        else:
                            raise

                    if not chunk:
                        pty_open = False
                        sel.unregister(master_fd)
                        continue

                    text = chunk.decode("utf-8", errors="replace")
                    pty_buf += text
                    last_pty_data = time.monotonic()

                    while "\n" in pty_buf:
                        line, pty_buf = pty_buf.split("\n", 1)
                        last_prompt_sent = ""
                        process_line(line)

                elif key.data == "stdin":
                    try:
                        chunk = os.read(stdin_fd, 4096)
                    except OSError as exc:
                        if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                            continue
                        chunk = b""

                    if not chunk:
                        shutting_down = True
                        emit({"type": "state", "state": "disconnecting"})
                        terminate_proc(proc)
                        break

                    stdin_buf += chunk.decode("utf-8", errors="replace")
                    while "\n" in stdin_buf:
                        cmd_line, stdin_buf = stdin_buf.split("\n", 1)
                        cmd_line = cmd_line.strip()
                        if not cmd_line:
                            continue
                        try:
                            cmd_obj = json.loads(cmd_line)
                        except json.JSONDecodeError:
                            continue

                        cmd = cmd_obj.get("cmd")
                        if cmd == "disconnect":
                            shutting_down = True
                            emit({"type": "state", "state": "disconnecting"})
                            emit({"type": "log", "line": "Desconectando VPN..."})
                            terminate_proc(proc)
                            break
                        elif cmd == "input" and pty_open:
                            answer = sanitize_single_line(str(cmd_obj.get("text") or ""))
                            if len(answer) >= 3:
                                secrets_to_redact.append(answer)
                            try:
                                os.write(master_fd, (answer + "\n").encode("utf-8"))
                            except OSError:
                                pass
                            last_prompt_sent = ""

            if pty_buf and (time.monotonic() - last_pty_data) > 0.25:
                partial = ANSI_RE.sub("", pty_buf).strip()
                if partial and partial != last_prompt_sent and PROMPT_RE.search(partial):
                    last_prompt_sent = partial
                    is_secret = bool(SECRET_PROMPT_RE.search(partial))
                    emit({"type": "prompt", "text": partial, "secret": is_secret})

            if not pty_open and proc.poll() is not None:
                break

        if pty_buf.strip():
            process_line(pty_buf)

        rc = proc.wait(timeout=5) if proc is not None else 0
        emit({"type": "state", "state": "disconnected"})
        emit({"type": "exit", "code": rc})
        return rc

    except Exception as exc:
        emit({"type": "error", "message": f"Error ejecutando openfortivpn: {exc}"})
        return 1
    finally:
        if proc is not None and proc.poll() is None:
            terminate_proc(proc)
        if master_fd is not None:
            try:
                os.close(master_fd)
            except OSError:
                pass
        safe_unlink(tmp_config)


if __name__ == "__main__":
    sys.exit(main())
