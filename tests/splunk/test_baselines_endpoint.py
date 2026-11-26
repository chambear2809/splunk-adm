"""Installed baseline endpoint checks in a distinct, task-owned disposable lab.

These checks do not qualify a source provider, Splunk Web, CSRF, backup or restore.
The management endpoint receives direct authenticated requests; browser proxy and
native CSRF behavior require separate installed qualification.
"""

import base64
import http.client
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import unittest
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab  # noqa: E402

ENDPOINT = "/servicesNS/nobody/splunk_adm/adm/dependency-monitoring"
CONFIG = "/servicesNS/nobody/splunk_adm/configs/conf-adm_baselines/persistence"
FAKE_ID = "00000000-0000-4000-8000-000000000000"


# Only these fixed paths are touched in the verified disposable container.
_CONFIG_SCRIPT = r"""
import base64, json, os, stat, sys
path = '/opt/splunk/etc/apps/splunk_adm/local/adm_baselines.conf'
parent = os.path.dirname(path)
if os.path.islink(parent):
    raise RuntimeError('unsafe configuration directory')
mode = sys.argv[1]
if mode == 'snapshot':
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        print(json.dumps({'exists': False}))
    else:
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError('unsafe configuration file')
        with open(path, 'rb') as source:
            data = base64.b64encode(source.read()).decode('ascii')
        print(json.dumps({'exists': True, 'data': data, 'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}))
elif mode == 'restore':
    snapshot = json.load(sys.stdin)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError('unsafe configuration file')
        os.unlink(path)
    if snapshot['exists']:
        os.makedirs(parent, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, snapshot['mode'])
        with os.fdopen(fd, 'wb') as destination:
            destination.write(base64.b64decode(snapshot['data'], validate=True))
            os.fchown(destination.fileno(), snapshot['uid'], snapshot['gid'])
            os.fchmod(destination.fileno(), snapshot['mode'])
else:
    raise RuntimeError('invalid operation')
"""

_DATABASE_SCRIPT = r"""
import json, os, stat
base = os.environ.get('SPLUNK_DB', '/opt/splunk/var/lib/splunk')
if not os.path.isabs(base) or os.path.islink(base):
    raise RuntimeError('unsafe storage root')
directory = os.path.join(base, 'splunk_adm_baselines')
path = os.path.join(directory, 'baselines.sqlite')
dirinfo, info = os.lstat(directory), os.lstat(path)
print(json.dumps({'directory': stat.S_ISDIR(dirinfo.st_mode), 'dir_mode': stat.S_IMODE(dirinfo.st_mode), 'dir_uid': dirinfo.st_uid, 'regular': stat.S_ISREG(info.st_mode), 'file_mode': stat.S_IMODE(info.st_mode), 'file_uid': info.st_uid, 'links': info.st_nlink}))
"""


def container_python(script, *args, input_data=None):
    identity = lab.task_identity()
    if identity is None:
        raise lab.LabError("requires task-owned lab")
    lab.verify_target()
    result = subprocess.run(
        [
            "docker",
            "exec",
            "-i",
            "--user",
            "root",
            identity[1],
            "python3",
            "-c",
            script,
            *args,
        ],
        input=input_data,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    return result.stdout


def restore_config(snapshot):
    container_python(_CONFIG_SCRIPT, "restore", input_data=json.dumps(snapshot))


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires task-owned lab")
class InstalledBaselinesTest(unittest.TestCase):
    def setUp(self):
        if lab.task_identity() is None:
            self.skipTest("requires distinct task-owned lab")
        lab.verify_target()
        snapshot = json.loads(container_python(_CONFIG_SCRIPT, "snapshot"))
        self.addCleanup(restore_config, snapshot)
        suffix = secrets.token_hex(5)
        self.roles = ["atlas_baseline_" + suffix + part for part in ("yes", "no")]
        self.users = [
            ("atlas_baseline_" + suffix + part, secrets.token_urlsafe(24))
            for part in ("yes", "no")
        ]
        for role, capabilities in zip(self.roles, (["adm_investigate"], [])):
            role_data = {"name": role, "capabilities": capabilities}
            if capabilities:
                role_data["imported_roles"] = "adm_viewer"
            lab._json(
                "POST",
                "/services/authorization/roles",
                role_data,
            )
            self.addCleanup(
                lab._json, "DELETE", "/services/authorization/roles/" + role
            )
        for (user, password), role in zip(self.users, self.roles):
            lab._json(
                "POST",
                "/services/authentication/users",
                {"name": user, "password": password, "roles": role},
            )
            self.addCleanup(
                lab._json, "DELETE", "/services/authentication/users/" + user
            )

    def request(
        self,
        method,
        path,
        body=None,
        key=None,
        *,
        user=0,
        content_type="application/json",
    ):
        name, password = self.users[user]
        headers = {
            "Authorization": "Basic "
            + base64.b64encode((name + ":" + password).encode()).decode()
        }
        if key is not None:
            headers["Idempotency-Key"] = key
        data = None if body is None else json.dumps(body).encode()
        if data is not None:
            headers["Content-Type"] = content_type
        separator = "&" if "?" in path else "?"
        req = urllib.request.Request(
            lab.MGMT + ENDPOINT + path + separator + "output_mode=json",
            method=method,
            headers=headers,
            data=data,
        )
        lab.verify_target()
        try:
            response = lab.urlopen(req, timeout=30)
        except urllib.error.HTTPError as response:
            with response:
                raw = response.read()
                try:
                    payload = json.loads(raw)
                except (UnicodeDecodeError, ValueError):
                    payload = None
                return response.code, payload
        with response:
            return response.status, json.loads(response.read())

    def duplicate_headers(self):
        lab.verify_target()
        address = urllib.parse.urlsplit(lab.MGMT)
        conn = http.client.HTTPSConnection(
            address.hostname, address.port, context=lab._CTX, timeout=30
        )
        name, password = self.users[0]
        try:
            conn.putrequest("GET", ENDPOINT + "/capabilities?output_mode=json")
            conn.putheader(
                "Authorization",
                "Basic " + base64.b64encode((name + ":" + password).encode()).decode(),
            )
            conn.putheader("X-Atlas-Test", "a")
            conn.putheader("X-Atlas-Test", "b")
            conn.endheaders()
            response = conn.getresponse()
            response.read()
            return response.status
        finally:
            conn.close()

    def test_disabled_auth_and_source_fail_closed(self):
        # The task-owned fixture must start from the package defaults. Do not
        # overwrite preexisting local configuration or assert it is shipped.
        config = lab._json("GET", CONFIG)["entry"][0]["content"]
        self.assertEqual(
            {key: config[key] for key in ("mode", "platform", "source_mode")},
            {
                "mode": "disabled",
                "platform": "unqualified",
                "source_mode": "unavailable",
            },
        )
        self.assertEqual(self.request("GET", "/capabilities", user=1)[0], 403)
        status, capability = self.request("GET", "/capabilities")
        self.assertEqual(status, 200)
        self.assertFalse(capability["available"])
        self.assertFalse(capability["sourceAvailable"])
        self.assertEqual(self.request("GET", "/baselines")[0], 503)
        # Keep source_mode unchanged; this is runtime testing, not qualification.
        lab._json(
            "POST", CONFIG, {"mode": "single_search_head", "platform": "enterprise"}
        )
        status, capability = self.request("GET", "/capabilities")
        self.assertEqual(status, 200)
        self.assertTrue(capability["available"])
        self.assertFalse(capability["sourceAvailable"])
        self.assertIn("source_unavailable", capability["qualificationReasons"])
        self.assertEqual(
            self.request("GET", "/baselines")[:2], (200, {"items": [], "next": None})
        )
        info = json.loads(container_python(_DATABASE_SCRIPT))
        self.assertTrue(info["directory"] and info["regular"])
        self.assertEqual(info["dir_mode"] & 0o077, 0)
        self.assertEqual(info["file_mode"] & 0o077, 0)
        self.assertEqual(info["dir_uid"], info["file_uid"])
        self.assertEqual(info["file_uid"], 41812)
        self.assertEqual(info["links"], 1)
        selection = "/capture?service=checkout&environment=lab&cluster=lab&namespace=lab&start=1&end=11"
        self.assertEqual(
            self.request("GET", selection)[:2], (422, {"error": "source_unavailable"})
        )
        self.assertEqual(self.request("GET", selection + "&start=2")[0], 400)
        cases = (
            ("/baselines", {"name": "x", "reference": "unavailable"}),
            (
                "/baselines/" + FAKE_ID + "/versions",
                {"expected_revision": 1, "reference": "unavailable"},
            ),
            (
                "/baselines/" + FAKE_ID + "/watches/w/evaluate",
                {
                    "expected_revision": 1,
                    "baseline_version": 1,
                    "reference": "unavailable",
                },
            ),
        )
        for index, (path, body) in enumerate(cases):
            with self.subTest(path=path):
                self.assertEqual(
                    self.request("POST", path, body, "request-" + str(index))[:2],
                    (422, {"error": "source_unavailable"}),
                )
        self.assertEqual(self.request("POST", "/baselines/purge", {}, "purge")[0], 403)
        self.assertEqual(
            self.request(
                "POST",
                "/baselines/" + FAKE_ID + "/share",
                {"expected_revision": 1, "member": "x", "grant": True},
                "media",
                content_type="text/plain",
            )[0],
            415,
        )
        self.assertEqual(self.duplicate_headers(), 400)
