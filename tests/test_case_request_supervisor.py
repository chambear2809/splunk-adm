"""Real child/pipe/retirement checks, isolated from the test runner's prctl."""

import io
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
uncertain_left=spec.get('uncertain_retirements',0)
if uncertain_left:
    real=s._retire
    def uncertain(p,*a):
        global uncertain_left
        if not (spec.get('skip_real') and uncertain_left):
            real(p,*a)
        if uncertain_left:
            uncertain_left-=1
            return False
        return True
    s._retire=uncertain
results=[]
for raw in spec['requests']:
    start=time.monotonic()
    result=s.supervise(json.dumps(raw),_worker_path=spec['worker'],_timeout=spec.get('timeout',2),_env=s._worker_environment())
    results.append({'result':result,'elapsed':time.monotonic()-start,'leaked':s.leaked_count()})
print(json.dumps({'results':results,'leaked':s.leaked_count()}),flush=True)
time.sleep(spec.get('linger',0))
"""


class CaseRequestSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.worker = self.root / "worker.py"
        self.worker.write_text(WORKER)
        self.marker = self.root / "worker-state.json"
        self.home = self.root / "splunk"
        self.home.joinpath("var/run/splunk").mkdir(parents=True, mode=0o755)
        self.env = {**os.environ, "SPLUNK_HOME": str(self.home)}

    def spec(self, requests, **options):
        return json.dumps(
            {
                "bin": str(BIN),
                "worker": str(self.worker),
                "requests": requests,
                **options,
            }
        ).encode()

    def run_requests(self, requests, **options):
        result = subprocess.run(
            [sys.executable, "-c", RUNNER],
            input=self.spec(requests, **options),
            capture_output=True,
            timeout=10,
            check=True,
            env=self.env,
        )
        return json.loads(result.stdout.splitlines()[0])

    def start_handler(self, requests, **options):
        """A lingering handler process; returns it once its requests finished."""
        handler = subprocess.Popen(
            [sys.executable, "-c", RUNNER],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=self.env,
        )
        self.addCleanup(handler.wait, 5)
        self.addCleanup(handler.kill)
        self.addCleanup(handler.stdout.close)
        handler.stdin.write(self.spec(requests, **options))
        handler.stdin.close()
        return handler, json.loads(handler.stdout.readline())

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
        self.assertEqual(value["leaked"], 0)

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
        self.assertEqual(value["leaked"], 0)

    @unittest.skipUnless(
        sys.platform == "linux", "requires Linux child-subreaper semantics"
    )
    def test_descendant_is_retired_and_reaped_before_success(self):
        value = self.run_requests([{"mode": "descendant"}])
        result = value["results"][0]["result"]
        self.assertEqual(result["status"], 200)
        self.assert_group_gone(result["payload"]["pid"])
        self.assertEqual(value["leaked"], 0)

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
                self.assertEqual(value["leaked"], 0)

    @unittest.skipUnless(
        sys.platform == "linux", "requires Linux child-subreaper semantics"
    )
    def test_uncertain_retirements_hold_slots_until_admission_closes(self):
        value = self.run_requests([{}] * 5, uncertain_retirements=100)
        self.assertEqual([v["result"]["status"] for v in value["results"]], [503] * 5)
        self.assertEqual([v["leaked"] for v in value["results"]], [1, 2, 3, 3, 3])

    @unittest.skipUnless(
        sys.platform == "linux", "requires Linux child-subreaper semantics"
    )
    def test_admission_recovers_once_leaked_group_is_proven_gone(self):
        value = self.run_requests([{"mode": "descendant"}, {}], uncertain_retirements=1)
        self.assertEqual([v["result"]["status"] for v in value["results"]], [503, 200])
        self.assertEqual([v["leaked"] for v in value["results"]], [1, 0])

    @unittest.skipUnless(
        sys.platform == "linux", "requires Linux child-subreaper semantics"
    )
    def test_recovery_signals_and_reaps_a_leaked_live_leader(self):
        value = self.run_requests(
            [{"marker": str(self.marker)}, {}], uncertain_retirements=1, skip_real=True
        )
        self.assertEqual([v["result"]["status"] for v in value["results"]], [503, 200])
        self.assertEqual([v["leaked"] for v in value["results"]], [1, 0])
        self.assert_group_gone(json.loads(self.marker.read_text())["pid"])

    def test_reused_pgid_of_live_worker_proves_old_group_gone_without_reaping(self):
        sys.path.insert(0, str(BIN))
        from adm_cases_lib import request_supervisor as supervisor
        from unittest.mock import patch

        class Reaped:
            pid = 424242
            returncode = 0

            def __init__(self):
                self.stdin, self.stdout = io.BytesIO(), io.BytesIO()

        with (
            patch.object(supervisor, "_unreaped", {Reaped.pid}),
            patch.object(supervisor.os, "waitpid") as reap,
            patch.object(supervisor.os, "killpg") as signal_group,
        ):
            self.assertTrue(supervisor._retire(Reaped(), 0.05))
            reap.assert_not_called()
            signal_group.assert_not_called()

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

    def test_non_linux_fails_closed_before_launch_without_leaking_slots(self):
        sys.path.insert(0, str(BIN))
        from adm_cases_lib import request_supervisor as supervisor
        from unittest.mock import patch

        with (
            patch.object(supervisor.sys, "platform", "darwin"),
            patch.object(supervisor, "_prepared", False),
            patch.object(supervisor.subprocess, "Popen") as launch,
        ):
            self.assertEqual(supervisor.supervise("{}")["status"], 503)
            self.assertEqual(supervisor.leaked_count(), 0)
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
        self.assertEqual(value["leaked"], 0)
        self.assert_group_gone(int(self.marker.read_text()))

    @unittest.skipUnless(
        sys.platform == "linux", "requires Linux child-subreaper semantics"
    )
    def test_concurrent_requests_share_bounded_process_wide_admission(self):
        runner = RUNNER.replace(
            "results=[]",
            """
import threading
original=s.supervise
env=s._worker_environment()
def hold(i,out):
    marker=spec['marker']+str(i)
    out.append(original(json.dumps({'mode':'timeout','marker':marker}),_worker_path=spec['worker'],_timeout=1.5,_env=env))
def wait_markers(n):
    end=time.monotonic()+3
    while not all(Path(spec['marker']+str(i)).exists() for i in range(n)) and time.monotonic()<end:time.sleep(.01)
held=[]
threads=[threading.Thread(target=hold,args=(0,held))]
threads[0].start()
wait_markers(1)
alongside=original('{}',_worker_path=spec['worker'],_timeout=2,_env=env)
for i in range(1,s.MAX_CONCURRENT):
    threads.append(threading.Thread(target=hold,args=(i,held)));threads[-1].start()
wait_markers(s.MAX_CONCURRENT)
busy=original('{}',_worker_path=spec['worker'],_timeout=2,_env=env)
for t in threads:t.join(timeout=5)
assert alongside['status']==200, alongside
assert busy['status']==503, busy
assert len(held)==s.MAX_CONCURRENT and all(r['status']==503 for r in held)
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
            env=self.env,
        )
        self.assertEqual(
            json.loads(result.stdout)["results"][0]["result"]["status"], 200
        )

    @unittest.skipUnless(
        sys.platform == "linux", "requires Linux child-subreaper semantics"
    )
    def test_admission_is_shared_across_handler_processes_and_freed_on_death(self):
        holders = []
        for _ in range(3):
            handler, value = self.start_handler(
                [{}], uncertain_retirements=1, linger=30
            )
            self.assertEqual(value["leaked"], 1)
            holders.append(handler)
        busy = self.run_requests([{}])
        self.assertEqual(busy["results"][0]["result"]["status"], 503)
        self.assertEqual(busy["leaked"], 0)
        holders[0].kill()
        holders[0].wait(timeout=5)
        freed = self.run_requests([{}])
        self.assertEqual(freed["results"][0]["result"]["status"], 200)

    def test_slots_are_exclusive_per_descriptor_and_released_on_close(self):
        sys.path.insert(0, str(BIN))
        from adm_cases_lib import request_supervisor as supervisor
        from unittest.mock import patch

        with patch.dict(os.environ, {"SPLUNK_HOME": str(self.home)}):
            held = [
                supervisor._acquire_slot() for _ in range(supervisor.MAX_CONCURRENT)
            ]
            self.assertNotIn(None, held)
            self.assertIsNone(supervisor._acquire_slot())
            supervisor._release_slot(held.pop())
            held.append(supervisor._acquire_slot())
            self.assertNotIn(None, held)
            for slot in held:
                supervisor._release_slot(slot)
        directory = self.home / "var/run/splunk/splunk_adm_request_slots"
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)

    def test_unsafe_slot_locations_fail_closed(self):
        sys.path.insert(0, str(BIN))
        from adm_cases_lib import request_supervisor as supervisor
        from unittest.mock import patch

        runtime = self.home / "var/run/splunk"
        directory = runtime / "splunk_adm_request_slots"
        target = self.root / "elsewhere"
        target.mkdir(mode=0o700)

        def refuses():
            with patch.dict(os.environ, {"SPLUNK_HOME": str(self.home)}):
                with self.assertRaises((OSError, RuntimeError)):
                    supervisor._acquire_slot()

        directory.symlink_to(target)
        refuses()
        directory.unlink()
        directory.mkdir(mode=0o700)
        (directory / "slot_0.lock").symlink_to(target / "slot")
        refuses()
        self.assertFalse((target / "slot").exists())
        (directory / "slot_0.lock").unlink()
        (directory / "slot_0.lock").touch(mode=0o644)
        os.chmod(directory / "slot_0.lock", 0o644)
        refuses()
        os.chmod(directory / "slot_0.lock", 0o600)
        os.chmod(directory, 0o755)
        refuses()
        os.chmod(directory, 0o700)
        os.chmod(runtime, 0o777)
        refuses()

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
