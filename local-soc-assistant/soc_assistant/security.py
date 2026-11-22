"""Defense in depth: Python socket guard; not an OS sandbox for native code."""
import ipaddress
import os
import sys
from contextlib import contextmanager
from pathlib import Path

_GUARD = False

def offline_guard():
    global _GUARD
    os.environ.update({"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "HF_HUB_DISABLE_TELEMETRY": "1",
                       "DO_NOT_TRACK": "1", "ANONYMIZED_TELEMETRY": "False"})
    if _GUARD:
        return
    def audit(event, args):
        if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto", "socket.bind"}:
            address = args[1] if event in {"socket.connect", "socket.bind"} else args[2] if event == "socket.sendto" else args[0]
            host = address[0] if isinstance(address, tuple) else address
            if host in {"localhost", None}:
                return
            try:
                if ipaddress.ip_address(str(host)).is_loopback:
                    return
            except ValueError:
                pass
            raise PermissionError("В рабочем режиме внешние сетевые обращения запрещены")
    sys.addaudithook(audit)
    _GUARD = True

class BusyError(RuntimeError):
    pass

@contextmanager
def analysis_lock(data_dir: Path):
    """OS-released cross-process lock; a crash does not leave a stale busy flag."""
    data_dir.mkdir(parents=True, exist_ok=True)
    handle = (data_dir / "analysis.lock").open("a+b")
    acquired = False
    try:
        if os.name == "nt":
            import msvcrt
            handle.seek(0, 2)
            if handle.tell() == 0:
                handle.write(b"0"); handle.flush()
            handle.seek(0)
            try: msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc: raise BusyError("Другой анализ уже выполняется") from exc
        else:
            import fcntl
            try: fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc: raise BusyError("Другой анализ уже выполняется") from exc
        acquired = True
        yield
    finally:
        if acquired:
            if os.name == "nt":
                import msvcrt
                handle.seek(0); msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()
