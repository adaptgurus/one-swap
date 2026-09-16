#!/usr/bin/env python3
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "appliance" / "oneswapd.py"
spec = importlib.util.spec_from_file_location("oneswapd", MODULE)
oneswapd = importlib.util.module_from_spec(spec)
assert spec.loader
sys.modules[spec.name] = oneswapd
spec.loader.exec_module(oneswapd)


class ApplianceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.scratch = root / "scratch"
        self.profiles = root / "profiles"
        self.scratch.mkdir()
        self.profiles.mkdir()
        self.oneswap = root / "oneswap"
        self.hyperv = root / "oneswap-hyperv"
        self.virtio = root / "virtio-win.iso"
        for path in (self.oneswap, self.hyperv, self.virtio):
            path.write_text("x", encoding="utf-8")
            path.chmod(0o700 if "oneswap" in path.name else 0o644)
        self.config = oneswapd.Config(
            listen_host="127.0.0.1", listen_port=9443,
            tls_cert=str(self.virtio), tls_key=str(self.virtio), client_ca=str(self.virtio),
            allowed_client_common_names=("layersentry-controller",),
            source_profiles_dir=str(self.profiles), state_db=str(root / "state.db"),
            scratch_root=str(self.scratch), oneswap_binary=str(self.oneswap),
            hyperv_binary=str(self.hyperv), virtio_win=str(self.virtio),
            qemu_ga_win=str(self.virtio), max_body_bytes=1048576,
            max_workers=2, execution_timeout_seconds=60, output_limit_bytes=65536,
        )
        self.store = oneswapd.StateStore(self.config.state_db)
        self.engine = oneswapd.Engine(self.config, self.store)

    def tearDown(self):
        self.engine.pool.shutdown(wait=True, cancel_futures=True)
        self.tmp.cleanup()

    def install_profile(self, tenant="tenant-a", source="hv-prod", platform="hyperv"):
        root = Path(self.tmp.name)
        one_auth = root / f"{source}.one_auth"
        config = root / f"{source}.yaml"
        one_auth.write_text("oneadmin:secret", encoding="utf-8")
        config.write_text(":datastore: 101\n", encoding="utf-8")
        one_auth.chmod(0o600)
        config.chmod(0o600)
        profile = {
            "tenant_id": tenant, "source_connection_id": source, "platform": platform,
            "one_auth": str(one_auth), "one_xmlrpc": "https://one.example/RPC2",
            "oneswap_config": str(config), "hyperv_connection": source,
            "http_transfer": True, "http_host": "10.0.0.50", "http_port": 29869,
        }
        name = oneswapd._atomic_profile_name(tenant, source)
        profile_path = self.profiles / name
        profile_path.write_text(json.dumps(profile), encoding="utf-8")
        profile_path.chmod(0o600)
        return profile

    def base_request(self, platform="hyperv", source="hv-prod", guest_os="windows"):
        return {
            "tenant_id": "tenant-a", "source_connection_id": source,
            "source_platform": platform, "source_vm_name": "source-vm-01",
            "phase": "convert", "mode": "standard", "guest_os": guest_os,
            "expected_guest_macs": ["00:15:5d:01:02:03"],
            "guest_network_profile": "", "target": {"datastore": "101", "network": "220"},
            "required_scratch_bytes": 1,
        }

    def test_windows_vmware_enforces_virtio_and_qemu_agent(self):
        profile = self.install_profile(source="vc-prod", platform="vmware")
        req = self.base_request(platform="vmware", source="vc-prod", guest_os="windows")
        argv = self.engine._vmware_command(req, profile)
        self.assertIn("--virtio", argv)
        self.assertIn("--win-qemu-ga", argv)
        self.assertIn("--http-transfer", argv)
        self.assertNotIn("--qemu-ga", argv)

    def test_linux_vmware_enforces_qemu_guest_agent(self):
        profile = self.install_profile(source="vc-prod", platform="vmware")
        req = self.base_request(platform="vmware", source="vc-prod", guest_os="linux")
        argv = self.engine._vmware_command(req, profile)
        self.assertIn("--qemu-ga", argv)
        self.assertNotIn("--virtio", argv)

    def test_hyperv_delta_commit_adds_source_off_guard(self):
        profile = self.install_profile()
        req = self.base_request()
        req.update({"phase": "delta_commit", "mode": "delta"})
        commands = self.engine.build_commands("op-123", req, profile)
        self.assertEqual(len(commands), 2)
        self.assertIn("--commit", commands[0])
        self.assertIn("--verify-source-off", commands[1])
        self.assertIn("--operation-id", commands[0])
        self.assertIn("--virtio", commands[0])
        self.assertIn("--win-qemu-ga", commands[0])

    def test_unqualified_cloud_adapter_fails_closed(self):
        self.install_profile(platform="aws")
        req = self.base_request(platform="aws")
        req["source_connection_id"] = "hv-prod"
        with self.assertRaises(oneswapd.RequestError) as ctx:
            self.engine.validate_request("op-aws", req)
        self.assertEqual(ctx.exception.status, 422)

    def test_operation_id_is_idempotent_but_request_is_immutable(self):
        req = self.base_request()
        first, created = self.store.create_or_get("op-1", req)
        self.assertTrue(created)
        self.assertEqual(first["state"], "QUEUED")
        _, created = self.store.create_or_get("op-1", req)
        self.assertFalse(created)
        changed = dict(req)
        changed["source_vm_name"] = "different-vm"
        with self.assertRaises(oneswapd.RequestError) as ctx:
            self.store.create_or_get("op-1", changed)
        self.assertEqual(ctx.exception.status, 409)

    def test_restart_converts_inflight_state_to_unknown(self):
        req = self.base_request()
        self.store.create_or_get("op-2", req)
        self.store.set_state("op-2", "RUNNING")
        replacement = oneswapd.StateStore(self.config.state_db)
        self.assertEqual(replacement.get("op-2")["state"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
