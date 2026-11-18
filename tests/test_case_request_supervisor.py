"""Real child/pipe/retirement checks, isolated from the test runner's prctl."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

BIN = Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm/bin"

WORKER = r"""
import json,os,signal,subprocess,sys,time
data=json.loads(sys.stdin.buffer.read())
mode=data.get('mode','success')
if 'marker' in data:
    with open(data['marker'],'w') as f: json.dump({'pid':os.getpid(),'pgid':os.getpgrp()},f)
if mode=='timeout': time.sleep(60)
if mode=='eof': sys.exit(1)
if mode=='oversize':
    sys.stdout.buffer.write((8*1024*1024+1).to_bytes(4,'big'));sys.stdout.buffer.flush();time.sleep(60)
if mode=='badjson':
    sys.stdout.buffer.write((1).to_bytes(4,'big')+b'x');sys.stdout.buffer.flush();time.sleep(60)
if mode=='truncated':
    sys.stdout.buffer.write((20).to_bytes(4,'big')+b'x');sys.stdout.buffer.flush();sys.exit(1)
if mode=='descendant':
    subprocess.Popen([sys.executable,'-c','import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)'])
secret=data.get('session',{}).get('authtoken','unused-secret')
result={'status':200,'payload':{'pid':os.getpid(),'token_in_argv':any(secret in a for a in sys.argv),'token_in_env':any(secret in v for v in os.environ.values())},'headers':{'Cache-Control':'no-store'}}
if mode=='badheaders':result['headers']['Location']='https://untrusted.example/'
raw=json.dumps(result).encode()
sys.stdout.buffer.write(len(raw).to_bytes(4,'big')+raw);sys.stdout.buffer.flush()
while True:time.sleep(60)
"""

RUNNER = r"""
import json,sys,time
from pathlib import Path
spec=json.load(sys.stdin)
sys.path.insert(0,spec['bin'])
from adm_cases_lib import request_supervisor as s
if spec.get('uncertain_retirement'):
    real=s._retire
    def uncertain(p):real(p);return False
    s._retire=uncertain
results=[]
for raw in spec['requests']:
    start=time.monotonic()
    result=s.supervise(json.dumps(raw),_worker_path=spec['worker'],_timeout=spec.get('timeout',2),_env=s._worker_environment())
    results.append({'result':result,'elapsed':time.monotonic()-start})
print(json.dumps({'results':results,'poisoned':s._poisoned}))
"""


class CaseRequestSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.worker = self.root / "worker.py"
        self.worker.write_text(WORKER)
        self.marker = self.root / "worker-state.json"

    def run_requests(self, requests, **options):
        spec = {
            "bin": str(BIN),
            "worker": str(self.worker),
            "requests": requests,
            **options,
        }
        result = subprocess.run(
            [sys.executable, "-c", RUNNER],
            input=json.dumps(spec).encode(),
            capture_output=True,
            timeout=10,
            check=True,
        )
        return json.loads(result.stdout)

    def assert_group_gone(self, pid):
        with self.assertRaises(ProcessLookupError):
            os.killpg(pid, 0)

    @unittest.skipUnless(
        sys.platform == "linux", "requires Linux child-subreaper semantics"
    )
    def test_valid_frame_keeps_credentials_out_of_arguments_and_retires_group(self):
        value = self.run_requests(
            [{"session": {"authtoken": "fixture-stdin-only-secret"}}]
        )
        result = value["results"][0]["result"]
        self.assertEqual(result["status"], 200)
        self.assertFalse(result["payload"]["token_in_argv"])
        self.assertFalse(result["payload"]["token_in_env"])
        self.assert_group_gone(result["payload"]["pid"])
        self.assertFalse(value["poisoned"])

    @unittest.skipUnless(
        sys.platform == "linux", "requires Linux child-subreaper semantics"
    )
    def test_timeout_kills_group_and_releases_admission_for_next_request(self):
        value = self.run_requests(
            [
                {"mode": "timeout", "marker": str(self.marker)},
                {},
            ],
            timeout=0.5,
        )
        self.assertEqual([v["result"]["status"] for v in value["results"]], [503, 200])
        self.assertLess(value["results"][0]["elapsed"], 3)
        self.assert_group_gone(json.loads(self.marker.read_text())["pid"])
        self.assertFalse(value["poisoned"])

    @unittest.skipUnless(
        sys.platform == "linux", "requires Linux child-subreaper semantics"
    )
    def test_descendant_is_retired_and_reaped_before_success(self):
        value = self.run_requests([{"mode": "descendant"}])
        result = value["results"][0]["result"]
        self.assertEqual(result["status"], 200)
        self.assert_group_gone(result["payload"]["pid"])
        self.assertFalse(value["poisoned"])

    @unittest.skipUnless(
        sys.platform == "linux", "requires Linux child-subreaper semantics"
    )
    def test_invalid_worker_responses_fail_closed_without_stranding_next_request(self):
        for mode in ("eof", "oversize", "badjson", "truncated", "badheaders"):
            with self.subTest(mode=mode):
                value = self.run_requests([{"mode": mode}, {}])
                self.assertEqual(
                    [v["result"]["status"] for v in value["results"]], [503, 200]
                )
                self.assertFalse(value["poisoned"])

    @unittest.skipUnless(
        sys.platform == "linux", "requires Linux child-subreaper semantics"
    )
    def test_uncertain_retirement_permanently_closes_process_admission(self):
        value = self.run_requests([{}, {}], uncertain_retirement=True)
        self.assertEqual([v["result"]["status"] for v in value["results"]], [503, 503])
        self.assertTrue(value["poisoned"])

    def test_input_size_limit_prevents_launch_and_includes_utf8_bytes(self):
        # No subprocess preparation is reached for oversized envelopes.
        sys.path.insert(0, str(BIN))
        from adm_cases_lib import request_supervisor as supervisor
        from unittest.mock import patch

        for raw in (
            "x" * (supervisor.MAX_INPUT + 1),
            "é" * (supervisor.MAX_INPUT // 2 + 1),
        ):
            with patch.object(supervisor.subprocess, "Popen") as launch:
                self.assertEqual(supervisor.supervise(raw)["status"], 413)
                launch.assert_not_called()

    def test_non_linux_fails_closed_before_launch_without_poisoning(self):
        sys.path.insert(0, str(BIN))
        from adm_cases_lib import request_supervisor as supervisor
        from unittest.mock import patch

        with (
            patch.object(supervisor.sys, "platform", "darwin"),
            patch.object(supervisor, "_prepared", False),
            patch.object(supervisor.subprocess, "Popen") as launch,
        ):
            self.assertEqual(supervisor.supervise("{}")["status"], 503)
            self.assertFalse(supervisor._poisoned)
            launch.assert_not_called()

    @unittest.skipUnless(
        sys.platform == "linux", "requires Linux child-subreaper semantics"
    )
    def test_nonreading_stdin_cannot_block_parent_or_leave_worker(self):
        self.worker.write_text(
            "import json,os,time;"
            f"open({str(self.marker)!r},'w').write(str(os.getpid()));"
            "time.sleep(60)"
        )
        value = self.run_requests([{"payload": "x" * 500000}], timeout=0.5)
        self.assertEqual(value["results"][0]["result"]["status"], 503)
        self.assertLess(value["results"][0]["elapsed"], 3)
        self.assertFalse(value["poisoned"])
        self.assert_group_gone(int(self.marker.read_text()))

    @unittest.skipUnless(
        sys.platform == "linux", "requires Linux child-subreaper semantics"
    )
    def test_concurrent_request_cannot_bypass_process_wide_admission(self):
        runner = RUNNER.replace(
            "results=[]",
            """
import threading
original=s.supervise
first=[]
t=threading.Thread(target=lambda:first.append(original(json.dumps({'mode':'timeout','marker':spec['marker']}),_worker_path=spec['worker'],_timeout=.8,_env=s._worker_environment())))
t.start()
end=time.monotonic()+2
while not Path(spec['marker']).exists() and time.monotonic()<end:time.sleep(.01)
busy=original('{}',_worker_path=spec['worker'],_timeout=2,_env=s._worker_environment())
t.join(timeout=4)
assert first and first[0]['status']==503 and busy['status']==503
results=[]""",
        )
        spec = {
            "bin": str(BIN),
            "worker": str(self.worker),
            "marker": str(self.marker),
            "requests": [{}],
        }
        result = subprocess.run(
            [sys.executable, "-c", runner],
            input=json.dumps(spec).encode(),
            capture_output=True,
            timeout=10,
            check=True,
        )
        self.assertEqual(
            json.loads(result.stdout)["results"][0]["result"]["status"], 200
        )

    def test_actual_worker_watchdog_covers_stalled_input_in_its_own_session(self):
        code = (
            f"import sys;sys.path.insert(0,{str(BIN)!r});"
            "from adm_cases_lib.request_worker import main;main(_watchdog_seconds=.2)"
        )
        child = subprocess.Popen(
            [sys.executable, "-c", code],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            self.assertEqual(child.wait(timeout=4), -signal.SIGKILL)
            self.assert_group_gone(child.pid)
            self.assertEqual(child.stdout.read(), b"")
        finally:
            for pipe in (child.stdin, child.stdout, child.stderr):
                pipe.close()
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=2)

    def test_direct_worker_invocation_refuses_without_signaling_callers_group(self):
        result = subprocess.run(
            [sys.executable, "-I", str(BIN / "adm_cases_lib/request_worker.py")],
            input=b"{}",
            capture_output=True,
            timeout=4,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")


if __name__ == "__main__":
    unittest.main()
