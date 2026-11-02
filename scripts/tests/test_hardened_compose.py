"""Validate the effective Compose boundary without starting any service."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class HardenedComposeTest(unittest.TestCase):
    def render(self, variables):
        # Do not let developer credentials or Docker endpoint settings influence
        # this configuration-only test, or print the rendered environment.
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("PENTAGI_", "DOCKER_"))}
        env.update(variables)
        with tempfile.NamedTemporaryFile(mode="w") as config:
            config.write("DOCKER_HOST=unix:///var/run/docker.sock\n"
                         "DOCKER_INSIDE=true\nDOCKER_NET_ADMIN=true\n"
                         "DOCKER_WORK_DIR=/host/work\nDOCKER_EGRESS_MODE=unrestricted\n"
                         "DOCKER_WORKER_ALLOW_PRIVILEGE_ESCALATION=true\n"
                         "EXTERNAL_SSL_INSECURE=true\n")
            config.flush()
            return subprocess.run(
                ["docker", "compose", "--env-file", config.name,
                 "-f", "docker-compose.yml", "-f", "docker-compose.hardened.yml",
                 "config", "--format", "json"], cwd=ROOT, env=env,
                capture_output=True, text=True, timeout=30, check=False)

    def test_required_deployment_inputs_fail_closed(self):
        required = {"PENTAGI_HARDENED_IMAGE": "pentagi-local:hardening-test",
                    "PENTAGI_WORKER_DOCKER_HOST": "tcp://worker.example:2376",
                    "PENTAGI_WORKER_TLS_DIR": "/tmp/synthetic-worker-client"}
        for missing in required:
            with self.subTest(missing=missing):
                result = self.render({k: v for k, v in required.items() if k != missing})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(missing, result.stderr)

    def test_override_removes_host_authority_and_forces_isolation(self):
        result = self.render({"PENTAGI_HARDENED_IMAGE": "pentagi-local:hardening-test",
                              "PENTAGI_WORKER_DOCKER_HOST": "tcp://worker.example:2376",
                              "PENTAGI_WORKER_TLS_DIR": "/tmp/synthetic-worker-client"})
        self.assertEqual(result.returncode, 0, result.stderr)
        service = json.loads(result.stdout)["services"]["pentagi"]
        self.assertEqual(service["user"], "0:0")
        env = service["environment"]
        self.assertEqual(service["image"], "pentagi-local:hardening-test")
        self.assertEqual(env["DOCKER_HOST"], "tcp://worker.example:2376")
        self.assertEqual(env["DOCKER_TLS_VERIFY"], "1")
        self.assertEqual(env["DOCKER_CERT_PATH"], "/opt/pentagi/docker/ssl")
        self.assertEqual(env["DOCKER_REQUIRE_ROOTLESS"], "true")
        self.assertEqual(env["DOCKER_EGRESS_MODE"], "isolated")
        self.assertEqual(env["DOCKER_NETWORK"], "pentagi-lab")
        for key in ("DOCKER_INSIDE", "DOCKER_NET_ADMIN",
                    "DOCKER_WORKER_ALLOW_PRIVILEGE_ESCALATION", "EXTERNAL_SSL_INSECURE"):
            self.assertEqual(env[key], "false")
        self.assertEqual(env["DOCKER_WORK_DIR"], "")
        self.assertEqual(env["DOCKER_SOCKET"], "")
        volumes = {v["target"]: v for v in service["volumes"]}
        self.assertNotIn("/var/run/docker.sock", volumes)
        self.assertNotIn("/root/.ollama", volumes)
        self.assertTrue(volumes["/opt/pentagi/docker/ssl"]["read_only"])
        self.assertEqual(set(service["cap_drop"]), {"ALL"})
        self.assertIn("no-new-privileges:true", service["security_opt"])
        self.assertEqual(float(service["cpus"]), 2)
        self.assertEqual(int(service["mem_limit"]), 4 << 30)
        self.assertEqual(service["mem_limit"], service["memswap_limit"])
        self.assertEqual(service["pids_limit"], 1024)


if __name__ == "__main__":
    unittest.main(verbosity=2)
