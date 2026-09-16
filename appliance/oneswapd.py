#!/usr/bin/env python3
"""LayerSentry OneSwap appliance control service.

LayerSentry remains the authoritative operation database. This service owns only
appliance-local execution/reconciliation state and never accepts source/cloud
credentials in API requests.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import ssl
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

VERSION = "1.0.0"
SAFE_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}\Z")
SAFE_VM = re.compile(r"\A[^\x00\r\n]{1,255}\Z")
SAFE_MAC = re.compile(r"\A(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\Z")
TERMINAL = {"SUCCEEDED", "FAILED", "UNKNOWN"}
MUTATING_PHASES = {
    "convert", "delta_prepare", "delta_commit", "delta_cleanup",
    "finalize_success", "verify_source_off",
}
ALLOWED_REQUEST_KEYS = {
    "migration_operation_id", "tenant_id", "source_connection_id",
    "source_platform", "source_vm_name", "phase", "mode", "guest_os",
    "expected_guest_macs", "guest_network_profile", "target",
    "required_scratch_bytes",
}
ALLOWED_TARGET_KEYS = {
    "datastore", "network", "one_cluster", "one_host", "one_sys_ds",
    "one_ds_cluster", "one_user", "one_group",
}


class RequestError(Exception):
    def __init__(self, message: str, status: int = HTTPStatus.BAD_REQUEST):
        super().__init__(message)
        self.status = int(status)


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _require_safe_id(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not SAFE_ID.fullmatch(text):
        raise RequestError(f"{label} is invalid")
    return text


def _require_vm_name(value: Any) -> str:
    text = str(value or "").strip()
    if not SAFE_VM.fullmatch(text):
        raise RequestError("source_vm_name is invalid")
    return text


def _safe_existing_file(path: Any, label: str, private: bool = False) -> str:
    resolved = Path(str(path or "")).expanduser().resolve()
    if not resolved.is_file():
        raise RequestError(f"{label} is unavailable on appliance", HTTPStatus.SERVICE_UNAVAILABLE)
    if private and (resolved.stat().st_mode & 0o077):
        raise RequestError(f"{label} permissions must not allow group/other access", HTTPStatus.SERVICE_UNAVAILABLE)
    return str(resolved)


def _safe_existing_path(path: Any, label: str) -> str:
    resolved = Path(str(path or "")).expanduser().resolve()
    if not resolved.exists():
        raise RequestError(f"{label} is unavailable on appliance", HTTPStatus.SERVICE_UNAVAILABLE)
    return str(resolved)


def _atomic_profile_name(tenant_id: str, source_connection_id: str) -> str:
    digest = hashlib.sha256(f"{tenant_id}\0{source_connection_id}".encode()).hexdigest()
    return digest + ".json"


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class Config:
    listen_host: str
    listen_port: int
    tls_cert: str
    tls_key: str
    client_ca: str
    allowed_client_common_names: tuple[str, ...]
    source_profiles_dir: str
    state_db: str
    scratch_root: str
    oneswap_binary: str
    hyperv_binary: str
    virtio_win: str
    qemu_ga_win: str
    max_body_bytes: int
    max_workers: int
    execution_timeout_seconds: int
    output_limit_bytes: int

    @classmethod
    def load(cls, path: str) -> "Config":
        raw = _read_json(Path(path))
        return cls(
            listen_host=str(raw.get("listen_host", "0.0.0.0")),
            listen_port=int(raw.get("listen_port", 9443)),
            tls_cert=_safe_existing_file(raw.get("tls_cert"), "TLS certificate"),
            tls_key=_safe_existing_file(raw.get("tls_key"), "TLS private key", private=True),
            client_ca=_safe_existing_file(raw.get("client_ca"), "client CA"),
            allowed_client_common_names=tuple(str(x) for x in raw.get("allowed_client_common_names", [])),
            source_profiles_dir=_safe_existing_path(raw.get("source_profiles_dir"), "source profiles directory"),
            state_db=str(Path(str(raw.get("state_db", "/var/lib/layersentry-oneswap/state.db"))).resolve()),
            scratch_root=_safe_existing_path(raw.get("scratch_root"), "conversion scratch root"),
            oneswap_binary=_safe_existing_file(raw.get("oneswap_binary", "/usr/bin/oneswap"), "oneswap binary"),
            hyperv_binary=_safe_existing_file(raw.get("hyperv_binary", "/usr/bin/oneswap-hyperv"), "oneswap-hyperv binary"),
            virtio_win=_safe_existing_path(raw.get("virtio_win"), "trusted virtio-win bundle"),
            qemu_ga_win=_safe_existing_path(raw.get("qemu_ga_win"), "trusted Windows QEMU Guest Agent bundle"),
            max_body_bytes=max(4096, min(int(raw.get("max_body_bytes", 1_048_576)), 4_194_304)),
            max_workers=max(1, min(int(raw.get("max_workers", 4)), 32)),
            execution_timeout_seconds=max(60, int(raw.get("execution_timeout_seconds", 86_400))),
            output_limit_bytes=max(4096, min(int(raw.get("output_limit_bytes", 65_536)), 1_048_576)),
        )


class StateStore:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.Lock()
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute(
                """CREATE TABLE IF NOT EXISTS operations (
                    operation_id TEXT PRIMARY KEY,
                    request_digest TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    state TEXT NOT NULL,
                    exit_code INTEGER,
                    stdout TEXT NOT NULL DEFAULT '',
                    stderr TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )"""
            )
        os.chmod(path, 0o600)
        self.mark_interrupted_unknown()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=30, isolation_level=None)

    def mark_interrupted_unknown(self) -> None:
        now = time.time()
        with self._lock, self._connect() as db:
            db.execute(
                "UPDATE operations SET state='UNKNOWN', stderr=CASE WHEN stderr='' THEN ? ELSE stderr END, updated_at=? WHERE state IN ('QUEUED','RUNNING')",
                ("oneswapd restarted during execution; observe source/target before retry", now),
            )

    def create_or_get(self, operation_id: str, request: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        digest = hashlib.sha256(_canonical_json(request)).hexdigest()
        encoded = _canonical_json(request).decode("utf-8")
        now = time.time()
        with self._lock, self._connect() as db:
            row = db.execute(
                "SELECT operation_id,request_digest,state,exit_code,stdout,stderr,created_at,updated_at FROM operations WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if row:
                if row[1] != digest:
                    raise RequestError("operation id already exists with a different request", HTTPStatus.CONFLICT)
                return self._row(row), False
            db.execute(
                "INSERT INTO operations(operation_id,request_digest,request_json,state,created_at,updated_at) VALUES(?,?,?,'QUEUED',?,?)",
                (operation_id, digest, encoded, now, now),
            )
            return self.get(operation_id), True

    def get(self, operation_id: str) -> dict[str, Any]:
        with self._connect() as db:
            row = db.execute(
                "SELECT operation_id,request_digest,state,exit_code,stdout,stderr,created_at,updated_at FROM operations WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
        if not row:
            raise RequestError("operation not found", HTTPStatus.NOT_FOUND)
        return self._row(row)

    @staticmethod
    def _row(row: tuple[Any, ...]) -> dict[str, Any]:
        return {
            "operation_id": row[0], "request_digest": row[1], "state": row[2],
            "exit_code": row[3], "stdout": row[4], "stderr": row[5],
            "created_at_unix": row[6], "updated_at_unix": row[7],
        }

    def set_state(self, operation_id: str, state: str, exit_code: int | None = None,
                  stdout: str = "", stderr: str = "") -> None:
        with self._lock, self._connect() as db:
            db.execute(
                "UPDATE operations SET state=?,exit_code=?,stdout=?,stderr=?,updated_at=? WHERE operation_id=?",
                (state, exit_code, stdout, stderr, time.time(), operation_id),
            )


class Engine:
    def __init__(self, config: Config, store: StateStore):
        self.config = config
        self.store = store
        self.pool = ThreadPoolExecutor(max_workers=config.max_workers, thread_name_prefix="oneswap")

    def profile(self, req: dict[str, Any]) -> dict[str, Any]:
        tenant = req["tenant_id"]
        source = req["source_connection_id"]
        path = Path(self.config.source_profiles_dir) / _atomic_profile_name(tenant, source)
        if not path.is_file():
            raise RequestError("registered source profile is not installed on appliance", HTTPStatus.NOT_FOUND)
        profile_path = Path(_safe_existing_file(path, "registered source profile", private=True))
        profile = _read_json(profile_path)
        if profile.get("tenant_id") != tenant or profile.get("source_connection_id") != source:
            raise RequestError("source profile identity mismatch", HTTPStatus.CONFLICT)
        if profile.get("platform") != req["source_platform"]:
            raise RequestError("source profile platform mismatch", HTTPStatus.CONFLICT)
        profile["oneswap_config"] = _safe_existing_file(profile.get("oneswap_config"), "OneSwap source configuration", private=True)
        profile["one_auth"] = _safe_existing_file(profile.get("one_auth"), "OpenNebula ONE_AUTH", private=True)
        one_xmlrpc = str(profile.get("one_xmlrpc", "")).strip()
        if not (one_xmlrpc.startswith("https://") or one_xmlrpc.startswith("http://")):
            raise RequestError("source profile OpenNebula endpoint is invalid", HTTPStatus.SERVICE_UNAVAILABLE)
        profile["one_xmlrpc"] = one_xmlrpc
        return profile

    def validate_request(self, operation_id: str, raw: Any) -> dict[str, Any]:
        _require_safe_id(operation_id, "operation id")
        if not isinstance(raw, dict):
            raise RequestError("request body must be a JSON object")
        unknown = set(raw) - ALLOWED_REQUEST_KEYS
        if unknown:
            raise RequestError("unsupported request field(s): " + ",".join(sorted(unknown)))
        req = dict(raw)
        req["migration_operation_id"] = _require_safe_id(req.get("migration_operation_id"), "migration_operation_id")
        req["tenant_id"] = _require_safe_id(req.get("tenant_id"), "tenant_id")
        req["source_connection_id"] = _require_safe_id(req.get("source_connection_id"), "source_connection_id")
        req["source_vm_name"] = _require_vm_name(req.get("source_vm_name"))
        platform = str(req.get("source_platform", "")).lower().strip()
        if platform not in {"vmware", "hyperv", "aws", "azure", "oci", "ibm", "kvm", "proxmox", "generic"}:
            raise RequestError("source_platform is unsupported")
        if platform not in {"vmware", "hyperv"}:
            raise RequestError(f"source platform {platform} is not yet live-qualified on this appliance", HTTPStatus.UNPROCESSABLE_ENTITY)
        req["source_platform"] = platform
        mode = str(req.get("mode", "standard")).lower().strip()
        if mode not in {"standard", "delta"}:
            raise RequestError("mode must be standard or delta")
        req["mode"] = mode
        phase = str(req.get("phase", "convert")).lower().strip()
        if phase not in MUTATING_PHASES and phase != "preflight":
            raise RequestError("phase is unsupported")
        req["phase"] = phase
        guest_os = str(req.get("guest_os", "")).lower().strip()
        if guest_os not in {"windows", "linux"}:
            raise RequestError("guest_os must be windows or linux from the LayerSentry guest authority")
        req["guest_os"] = guest_os
        macs = req.get("expected_guest_macs", [])
        if not isinstance(macs, list) or len(macs) > 64:
            raise RequestError("expected_guest_macs must be an array")
        canonical_macs = []
        for value in macs:
            text = str(value).lower().strip()
            if not SAFE_MAC.fullmatch(text):
                raise RequestError(f"invalid guest MAC {value!r}")
            canonical_macs.append(text)
        req["expected_guest_macs"] = sorted(set(canonical_macs))
        profile = str(req.get("guest_network_profile", "")).strip()
        if len(profile) > 262_144 or any(c in profile for c in "\r\n\x00"):
            raise RequestError("guest_network_profile is invalid")
        req["guest_network_profile"] = profile
        target = req.get("target", {})
        if not isinstance(target, dict) or set(target) - ALLOWED_TARGET_KEYS:
            raise RequestError("target contains unsupported fields")
        req["target"] = target
        required = int(req.get("required_scratch_bytes", 0) or 0)
        if required < 0:
            raise RequestError("required_scratch_bytes must be non-negative")
        req["required_scratch_bytes"] = required
        if phase in {"convert", "delta_prepare"} and required <= 0:
            raise RequestError("required_scratch_bytes is required before conversion/prepare")
        if required and shutil.disk_usage(self.config.scratch_root).free < required:
            raise RequestError("conversion scratch capacity is insufficient", HTTPStatus.INSUFFICIENT_STORAGE)
        self.profile(req)
        return req

    def submit(self, operation_id: str, req: dict[str, Any]) -> dict[str, Any]:
        current, created = self.store.create_or_get(operation_id, req)
        if created:
            self.pool.submit(self._execute, operation_id, req)
        return current

    def _execute(self, operation_id: str, req: dict[str, Any]) -> None:
        self.store.set_state(operation_id, "RUNNING")
        try:
            profile = self.profile(req)
            commands = self.build_commands(req, profile)
            env = os.environ.copy()
            env.update({
                "ONE_AUTH": profile["one_auth"],
                "ONE_XMLRPC": profile["one_xmlrpc"],
                "TMPDIR": self.config.scratch_root,
            })
            all_out: list[str] = []
            all_err: list[str] = []
            last_code = 0
            for argv in commands:
                completed = subprocess.run(
                    argv, env=env, cwd=self.config.scratch_root, shell=False,
                    capture_output=True, text=True, timeout=self.config.execution_timeout_seconds,
                    check=False,
                )
                last_code = int(completed.returncode)
                all_out.append(completed.stdout or "")
                all_err.append(completed.stderr or "")
                if completed.returncode != 0:
                    state = "FAILED" if req["phase"] == "preflight" else "UNKNOWN"
                    self.store.set_state(operation_id, state, last_code,
                                         self._cap("".join(all_out)), self._cap("".join(all_err)))
                    return
            self.store.set_state(operation_id, "SUCCEEDED", last_code,
                                 self._cap("".join(all_out)), self._cap("".join(all_err)))
        except subprocess.TimeoutExpired as exc:
            timeout_out = self._cap(exc.stdout or "")
            timeout_err = self._cap(exc.stderr or "")
            self.store.set_state(operation_id, "UNKNOWN", None, timeout_out,
                                 self._cap(timeout_err + "\nexecution timed out after dispatch"))
        except Exception as exc:  # Fail closed; never fabricate a definitive result.
            self.store.set_state(operation_id, "UNKNOWN", None, "", self._cap(str(exc)))

    def _cap(self, value: str | bytes) -> str:
        if isinstance(value, bytes):
            text = value.decode("utf-8", errors="replace")
        else:
            text = str(value or "")
        encoded = text.encode("utf-8", errors="replace")
        if len(encoded) <= self.config.output_limit_bytes:
            return text
        return encoded[-self.config.output_limit_bytes:].decode("utf-8", errors="replace")

    def build_commands(self, req: dict[str, Any], profile: dict[str, Any]) -> list[list[str]]:
        if req["source_platform"] == "vmware":
            return [self._vmware_command(req, profile)]
        migration_operation_id = req["migration_operation_id"]
        command = self._hyperv_command(migration_operation_id, req, profile)
        commands = [command]
        if req["phase"] == "delta_commit":
            guard_req = dict(req)
            guard_req["phase"] = "verify_source_off"
            commands.append(self._hyperv_command(migration_operation_id, guard_req, profile))
        return commands

    def _guest_args(self, req: dict[str, Any]) -> list[str]:
        if req["guest_os"] == "windows":
            return ["--virtio", self.config.virtio_win, "--win-qemu-ga", self.config.qemu_ga_win]
        return ["--qemu-ga"]

    @staticmethod
    def _target_args(target: dict[str, Any]) -> list[str]:
        mapping = {
            "datastore": "--datastore", "network": "--network", "one_cluster": "--one-cluster",
            "one_host": "--one-host", "one_sys_ds": "--one-sys-ds", "one_ds_cluster": "--one-ds-cluster",
            "one_user": "--one-user", "one_group": "--one-group",
        }
        args: list[str] = []
        for key, flag in mapping.items():
            value = target.get(key)
            if value is None or value == "":
                continue
            if isinstance(value, list):
                value = ",".join(str(v) for v in value)
            args.extend([flag, str(value)])
        return args

    def _vmware_command(self, req: dict[str, Any], profile: dict[str, Any]) -> list[str]:
        argv = [self.config.oneswap_binary, "convert", req["source_vm_name"], "--config-file", profile["oneswap_config"]]
        phase = req["phase"]
        if phase == "preflight":
            argv.append("--dry-run")
        elif phase == "delta_prepare":
            argv.extend(["--delta", "--delta-prepare"])
        elif phase == "delta_commit":
            argv.extend(["--delta", "--delta-commit"])
        elif phase == "delta_cleanup":
            argv.extend(["--delta", "--delta-cleanup"])
        elif phase != "convert":
            raise RequestError(f"VMware phase {phase} is unsupported")
        argv.extend(self._guest_args(req))
        argv.extend(self._target_args(req["target"]))
        if profile.get("http_transfer", True):
            argv.append("--http-transfer")
            if profile.get("http_host"):
                argv.extend(["--http-host", str(profile["http_host"])])
            if profile.get("http_port"):
                argv.extend(["--http-port", str(int(profile["http_port"]))])
        return argv

    def _hyperv_command(self, operation_id: str, req: dict[str, Any], profile: dict[str, Any]) -> list[str]:
        connection = _require_safe_id(profile.get("hyperv_connection", req["source_connection_id"]), "Hyper-V connection profile")
        argv = [self.config.hyperv_binary, req["source_vm_name"]]
        phase = req["phase"]
        hot_flags = {
            "preflight": "--preflight", "delta_prepare": "--prepare", "delta_commit": "--commit",
            "delta_cleanup": "--cleanup", "finalize_success": "--finalize-success",
            "verify_source_off": "--verify-source-off",
        }
        if phase in hot_flags:
            argv.extend(["--hot", hot_flags[phase], "--operation-id", operation_id])
        elif phase != "convert":
            raise RequestError(f"Hyper-V phase {phase} is unsupported")
        argv.extend(["--hyperv-connection", connection, "--config-file", profile["oneswap_config"], "--guest-os", req["guest_os"]])
        if req["expected_guest_macs"]:
            argv.extend(["--expected-guest-macs", ",".join(req["expected_guest_macs"])])
        if req["guest_network_profile"]:
            argv.extend(["--guest-network-profile", req["guest_network_profile"]])
        argv.extend(self._guest_args(req))
        argv.extend(self._target_args(req["target"]))
        if profile.get("http_transfer", True):
            argv.append("--http-transfer")
            if profile.get("http_host"):
                argv.extend(["--http-host", str(profile["http_host"])])
            if profile.get("http_port"):
                argv.extend(["--http-port", str(int(profile["http_port"]))])
        return argv


class APIHandler(BaseHTTPRequestHandler):
    server_version = "LayerSentry-OneSwap/1"
    protocol_version = "HTTP/1.1"

    @property
    def engine(self) -> Engine:
        return self.server.engine  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        print(json.dumps({"remote": self.client_address[0], "message": fmt % args}), flush=True)

    def _authorize_client(self) -> None:
        cert = self.connection.getpeercert()
        if not cert:
            raise RequestError("client certificate is required", HTTPStatus.UNAUTHORIZED)
        allowed = set(self.engine.config.allowed_client_common_names)
        if not allowed:
            return
        common_names = [value for rdn in cert.get("subject", ()) for key, value in rdn if key == "commonName"]
        if not set(common_names) & allowed:
            raise RequestError("client certificate identity is not authorized", HTTPStatus.FORBIDDEN)

    def _operation_id(self) -> str:
        parts = [part for part in self.path.split("?")[0].split("/") if part]
        if len(parts) != 3 or parts[:2] != ["v1", "operations"]:
            raise RequestError("route not found", HTTPStatus.NOT_FOUND)
        return _require_safe_id(parts[2], "operation id")

    def _json_body(self) -> Any:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise RequestError("Content-Length is required", HTTPStatus.LENGTH_REQUIRED)
        length = int(raw_length)
        if length <= 0 or length > self.engine.config.max_body_bytes:
            raise RequestError("request body size is invalid", HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        if self.headers.get_content_type() != "application/json":
            raise RequestError("Content-Type must be application/json", HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
        try:
            return json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError) as exc:
            raise RequestError(f"invalid JSON: {exc}") from exc

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = _canonical_json(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        try:
            self._authorize_client()
            if self.path.split("?")[0] == "/v1/healthz":
                free = shutil.disk_usage(self.engine.config.scratch_root).free
                self._send(HTTPStatus.OK, {"status": "ok", "version": VERSION, "scratch_free_bytes": free})
                return
            operation_id = self._operation_id()
            self._send(HTTPStatus.OK, self.engine.store.get(operation_id))
        except RequestError as exc:
            self._send(exc.status, {"error": str(exc)})
        except Exception:
            self._send(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal server error"})

    def do_POST(self) -> None:
        try:
            self._authorize_client()
            operation_id = self._operation_id()
            req = self.engine.validate_request(operation_id, self._json_body())
            record = self.engine.submit(operation_id, req)
            status = HTTPStatus.OK if record["state"] in TERMINAL else HTTPStatus.ACCEPTED
            self._send(status, record)
        except RequestError as exc:
            self._send(exc.status, {"error": str(exc)})
        except Exception:
            self._send(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal server error"})


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], handler: type[APIHandler], engine: Engine):
        super().__init__(address, handler)
        self.engine = engine


def build_tls(config: Config) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(config.tls_cert, config.tls_key)
    context.load_verify_locations(cafile=config.client_ca)
    return context


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=os.environ.get("ONESWAPD_CONFIG", "/etc/layersentry/oneswapd/config.json"))
    parser.add_argument("--check", action="store_true", help="validate configuration and exit")
    args = parser.parse_args()
    config = Config.load(args.config)
    store = StateStore(config.state_db)
    engine = Engine(config, store)
    if args.check:
        print(json.dumps({"status": "ok", "version": VERSION}))
        return 0
    server = Server((config.listen_host, config.listen_port), APIHandler, engine)
    server.socket = build_tls(config).wrap_socket(server.socket, server_side=True)
    server.serve_forever(poll_interval=0.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
