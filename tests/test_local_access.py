import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from io import StringIO

from tools.check_local_access import (
    main,
    validate_credentials,
    validate_kubeconfig,
    parse_expectations,
)


def credentials(**overrides):
    values = {
        "cloud": {
            "SPLUNK_PLATFORM": "cloud",
            "SPLUNK_TARGET_ROLE": "search-tier",
            "SPLUNK_CLOUD_STACK": "atlas",
            "SPLUNK_URI": "https://atlas.splunkcloud.com:8089",
            "SPLUNK_USER": "admin",
            "SPLUNK_PASS": "secret",
            "SPLUNK_VERIFY_SSL": "true",
        },
        "hf": {
            "SPLUNK_PLATFORM": "enterprise",
            "SPLUNK_TARGET_ROLE": "heavy-forwarder",
            "SPLUNK_URI": "https://hf.example:8089",
            "SPLUNK_USER": "admin",
            "SPLUNK_PASS": "secret",
            "SPLUNK_VERIFY_SSL": "true",
            "SPLUNK_SSH_HOST": "10.0.0.20",
            "SPLUNK_SSH_USER": "splunk",
            "SPLUNK_SSH_KNOWN_HOSTS_FILE": "/tmp/known_hosts",
            "SPLUNK_SSH_AUTH_METHOD": "key",
            "SPLUNK_SSH_ALLOW_TOFU": "false",
            "SPLUNK_CA_CERT": "/opt/splunk/etc/auth/cacert.pem",
            "SPLUNK_HEC_URL": "https://10.237.100.70:8088/services/collector/event",
            "ACS_SERVER": "acs.example",
            "STACK_TOKEN": "literal-token",
            "STACK_TOKEN_USER": "stack-user",
        },
        "enterprise": {
            "SPLUNK_PLATFORM": "enterprise",
            "SPLUNK_TARGET_ROLE": "standalone",
            "SPLUNK_URI": "https://SplunkServerDefaultCert:8089",
            "SPLUNK_USER": "admin",
            "SPLUNK_PASS": "secret",
            "SPLUNK_VERIFY_SSL": "true",
            "SPLUNK_SSH_HOST": "10.237.100.70",
            "SPLUNK_SSH_USER": "splunk",
            "SPLUNK_SSH_KNOWN_HOSTS_FILE": "/tmp/known_hosts",
            "SPLUNK_SSH_AUTH_METHOD": "key",
            "SPLUNK_SSH_ALLOW_TOFU": "false",
            "SPLUNK_CA_CERT": "/opt/splunk/etc/auth/cacert.pem",
        },
    }
    for profile, fields in overrides.items():
        values[profile].update(fields)
    return (
        'SPLUNK_PROFILE="enterprise"\n'
        + "\n".join(
            f"PROFILE_{profile}__{key}={json.dumps(value)}"
            for profile, fields in values.items()
            for key, value in fields.items()
        )
        + "\n"
    )


def target_expectations(host="192.0.2.70", uri="https://splunk.example.test:8089"):
    return {
        "enterprise": {
            "ssh_host": host,
            "search_uri": uri,
            "ca_path": "/opt/splunk/etc/auth/cacert.pem",
            "hec_url": f"https://{host}:8088/services/collector/event",
        }
    }


class LocalAccessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.cred = self.root / "credentials"
        self.cred.write_text(credentials())
        self.cred.chmod(0o600)

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid_profiles_and_enterprise_default(self):
        result = validate_credentials(self.cred)
        self.assertEqual(result["default_profile"], "enterprise")
        self.assertTrue(all(p["valid"] for p in result["profiles"].values()))

    def test_ca_is_deferred_until_an_explicit_expectation_is_supplied(self):
        self.cred.write_text(
            credentials(
                hf={"SPLUNK_CA_CERT": ""},
                enterprise={"SPLUNK_CA_CERT": ""},
            )
        )
        self.cred.chmod(0o600)
        result = validate_credentials(self.cred)["profiles"]
        self.assertTrue(result["hf"]["valid"])
        self.assertTrue(result["enterprise"]["valid"])

    def test_enterprise_hec_url_is_optional_but_exact_when_present(self):
        self.assertTrue(
            validate_credentials(self.cred)["profiles"]["enterprise"]["valid"]
        )
        expectations = target_expectations()
        self.cred.write_text(
            credentials(
                enterprise={
                    "SPLUNK_HEC_URL": "http://10.237.100.70:8088/services/collector/event"
                }
            )
        )
        self.cred.chmod(0o600)
        self.assertIn(
            "enterprise_hec_url_mismatch",
            validate_credentials(self.cred, expectations)["profiles"]["enterprise"][
                "errors"
            ],
        )
        self.cred.write_text(
            credentials(
                cloud={
                    "SPLUNK_HEC_URL": "https://10.237.100.70:8088/services/collector/event"
                }
            )
        )
        self.cred.chmod(0o600)
        self.assertIn(
            "cloud_hec_forbidden",
            validate_credentials(self.cred)["profiles"]["cloud"]["errors"],
        )

    def test_expectations_allow_another_target_without_changing_security_gates(self):
        alternate = target_expectations(
            host="192.0.2.70", uri="https://splunk.example.test:8089"
        )
        self.cred.write_text(
            credentials(
                enterprise={
                    "SPLUNK_SSH_HOST": "192.0.2.70",
                    "SPLUNK_URI": "https://splunk.example.test:8089",
                    "SPLUNK_HEC_URL": "https://192.0.2.70:8088/services/collector/event",
                }
            )
        )
        self.cred.chmod(0o600)
        self.assertTrue(
            validate_credentials(self.cred, alternate)["profiles"]["enterprise"][
                "valid"
            ]
        )
        custom_port = target_expectations(
            host="192.0.2.70", uri="https://splunk.example.test:9443"
        )
        self.cred.write_text(
            credentials(
                enterprise={
                    "SPLUNK_SSH_HOST": "192.0.2.70",
                    "SPLUNK_URI": "https://splunk.example.test:9443",
                    "SPLUNK_HEC_URL": "https://192.0.2.70:8088/services/collector/event",
                }
            )
        )
        self.cred.chmod(0o600)
        self.assertTrue(
            validate_credentials(self.cred, custom_port)["profiles"]["enterprise"][
                "valid"
            ]
        )
        hf_expectations = {
            "hf": {
                "search_uri": "https://hf.example.test:9443",
                "ca_path": "/opt/splunk/etc/auth/cacert.pem",
            }
        }
        self.cred.write_text(
            credentials(
                hf={
                    "SPLUNK_URI": "https://hf.example.test:9443",
                    "SPLUNK_CA_CERT": "/opt/splunk/etc/auth/cacert.pem",
                }
            )
        )
        self.cred.chmod(0o600)
        self.assertTrue(
            validate_credentials(self.cred, hf_expectations)["profiles"]["hf"]["valid"]
        )
        self.assertTrue(
            validate_credentials(
                self.cred,
                {"enterprise": {**alternate["enterprise"], "ca_path": "relative.pem"}},
            )["profiles"]["enterprise"]["valid"]
            is False
        )

    def test_unknown_profile_field_is_rejected(self):
        self.cred.write_text(credentials(enterprise={"SPLUNK_UNSUPPORTED": "x"}))
        self.cred.chmod(0o600)
        result = validate_credentials(self.cred)
        self.assertIn("unknown_field", result["profiles"]["enterprise"]["errors"])

    def test_expectations_file_is_owner_only_nonsecret_json(self):
        path = self.root / "expectations.json"
        path.write_text(json.dumps({"profiles": target_expectations()}))
        path.chmod(0o600)
        parsed, errors = parse_expectations(path)
        self.assertFalse(errors)
        self.assertEqual(parsed["enterprise"]["ssh_host"], "192.0.2.70")

    def test_expectations_reject_duplicate_unknown_and_missing_contracts(self):
        path = self.root / "expectations.json"
        path.write_text('{"profiles": {}, "profiles": {}}')
        path.chmod(0o600)
        self.assertEqual(parse_expectations(path)[1], ["duplicate_expectation_key"])
        path.write_text('{"profiles": {"other": {}}}')
        self.assertEqual(parse_expectations(path)[1], ["unknown_expectation_profile"])
        path.write_text('{"unexpected": {}}')
        self.assertEqual(parse_expectations(path)[1], ["missing_expectations_profiles"])

    def test_missing_profile_and_required_value(self):
        self.cred.write_text(credentials())
        self.cred.chmod(0o600)
        text = "\n".join(
            line
            for line in self.cred.read_text().splitlines()
            if not line.startswith("PROFILE_hf__")
        )
        self.cred.write_text(text + "\n")
        result = validate_credentials(self.cred)
        self.assertFalse(result["profiles"]["hf"]["valid"])
        self.assertIn("missing_splunk_platform", result["profiles"]["hf"]["errors"])

    def test_cross_target_leakage_and_strict_urls(self):
        self.cred.write_text(
            credentials(
                cloud={
                    "SPLUNK_SSH_HOST": "leak",
                    "SPLUNK_URI": "https://atlas.splunkcloud.com:8089/",
                }
            )
        )
        self.cred.chmod(0o600)
        cloud = validate_credentials(self.cred)["profiles"]["cloud"]
        self.assertFalse(cloud["valid"])
        self.assertIn("cloud_ssh_leakage", cloud["errors"])
        self.assertIn("cloud_endpoint_mismatch", cloud["errors"])
        self.cred.write_text(
            credentials(
                cloud={
                    "SPLUNK_CLOUD_STACK": "atlas.",
                    "SPLUNK_URI": "https://atlas..splunkcloud.com:8089",
                }
            )
        )
        self.cred.chmod(0o600)
        self.assertIn(
            "invalid_stack",
            validate_credentials(self.cred)["profiles"]["cloud"]["errors"],
        )
        self.cred.write_text(
            credentials(cloud={"SPLUNK_URI": "https://atlas.splunkcloud.com:bad"})
        )
        self.cred.chmod(0o600)
        self.assertIn(
            "search_uri_malformed",
            validate_credentials(self.cred)["profiles"]["cloud"]["errors"],
        )
        self.cred.write_text(credentials(cloud={"SPLUNK_URI": "https://:8089"}))
        self.cred.chmod(0o600)
        self.assertIn(
            "search_uri_not_strict_https",
            validate_credentials(self.cred)["profiles"]["cloud"]["errors"],
        )
        self.cred.write_text(
            credentials(
                cloud={
                    "SPLUNK_SEARCH_API_URI": "https://different.example:8089",
                }
            )
        )
        self.cred.chmod(0o600)
        self.assertIn(
            "uri_alias_conflict",
            validate_credentials(self.cred)["profiles"]["cloud"]["errors"],
        )

    def test_permissions_and_symlink_rejected(self):
        self.cred.chmod(0o640)
        self.assertIn(
            "permissions_not_owner_only",
            validate_credentials(self.cred)["profiles"]["cloud"]["errors"],
        )
        link = self.root / "link"
        link.symlink_to(self.cred)
        self.assertIn(
            "symlink_forbidden",
            validate_credentials(link)["profiles"]["cloud"]["errors"],
        )

    def test_substitution_and_shell_syntax_are_not_interpreted(self):
        self.cred.write_text(
            credentials(enterprise={"SPLUNK_PASS": "$(touch /tmp/pwned);$HOME`echo x`"})
        )
        self.cred.chmod(0o600)
        result = validate_credentials(self.cred)["profiles"]["enterprise"]
        self.assertTrue(result["valid"])

    def test_kubeconfig_command_is_non_raw_and_context_is_checked(self):
        kube = self.root / "config"
        kube.write_text("fixture")
        kube.chmod(0o600)
        doc = {
            "current-context": "ctx",
            "contexts": [
                {"name": "ctx", "context": {"cluster": "cluster", "user": "user"}}
            ],
            "clusters": [
                {
                    "name": "cluster",
                    "cluster": {
                        "server": "https://kube.example",
                        "certificate-authority-data": "Y2E=",
                    },
                }
            ],
            "users": [{"name": "user", "user": {"token": "redacted"}}],
        }
        with mock.patch("tools.check_local_access.subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout=json.dumps(doc))
            result = validate_kubeconfig(kube)
        self.assertTrue(result["valid"])
        argv = run.call_args.args[0]
        self.assertNotIn("--raw", argv)
        self.assertEqual(
            argv[-3:], ["config", "view", "-o"] if False else ["view", "-o", "json"]
        )

    def test_kubeconfig_rejects_exec_insecure_and_missing_ca(self):
        kube = self.root / "config"
        kube.write_text("fixture")
        kube.chmod(0o600)
        doc = {
            "current-context": "ctx",
            "contexts": [
                {"name": "ctx", "context": {"cluster": "cluster", "user": "user"}}
            ],
            "clusters": [
                {
                    "name": "cluster",
                    "cluster": {
                        "server": "https://kube.example",
                        "insecure-skip-tls-verify": True,
                    },
                }
            ],
            "users": [{"name": "user", "user": {"exec": {"command": "sh"}}}],
        }
        with mock.patch("tools.check_local_access.subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout=json.dumps(doc))
            result = validate_kubeconfig(kube)
        self.assertFalse(result["valid"])
        self.assertIn("exec_auth_provider_forbidden", result["errors"])
        self.assertIn("cluster_ca_required", result["errors"])

    def test_cli_emits_status_only_with_mocked_kubeconfig(self):
        kube = self.root / "config"
        kube.write_text("fixture")
        kube.chmod(0o600)
        doc = {
            "current-context": "ctx",
            "contexts": [{"name": "ctx", "context": {"cluster": "c", "user": "u"}}],
            "clusters": [
                {
                    "name": "c",
                    "cluster": {
                        "server": "https://kube",
                        "certificate-authority-data": "Y2E=",
                    },
                }
            ],
            "users": [{"name": "u", "user": {"token": "not-printed"}}],
        }
        captured = StringIO()
        with (
            mock.patch("tools.check_local_access.subprocess.run") as run,
            mock.patch("sys.stdout", captured),
        ):
            run.return_value = mock.Mock(returncode=0, stdout=json.dumps(doc))
            code = main(["--credentials", str(self.cred), "--kubeconfig", str(kube)])
        self.assertEqual(code, 0)
        output = captured.getvalue()
        self.assertNotIn("secret", output)
        parsed = json.loads(output)
        self.assertTrue(parsed["kubeconfig"]["valid"])


if __name__ == "__main__":
    unittest.main()
