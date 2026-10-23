"""Offline document/request lifetime regressions for viewer qualification."""

from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")

FIXTURE = r"""
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
const target = 'http://127.0.0.1:8000/en-US/app/splunk_adm/data_health';
const endpoint = 'http://127.0.0.1:8000/en-US/splunkd/__raw/servicesNS/nobody/splunk_adm/adm/deployment-settings?output_mode=json';
const paths = [['settings', '/adm/deployment-settings']];
const timers = new Set();
function setTimeout(callback, delay) {
  const timer = globalThis.setTimeout(() => {
    timers.delete(timer);
    callback();
  }, delay);
  timers.add(timer);
  return timer;
}
function clearTimeout(timer) {
  timers.delete(timer);
  globalThis.clearTimeout(timer);
}
class Page extends EventEmitter {
  constructor() {
    super();
    this.currentURL = target.replace('data_health', 'applications');
    this.frame = {url: () => this.currentURL};
  }
  mainFrame() { return this.frame; }
  commit(url = target) {
    this.currentURL = url;
    this.emit('framenavigated', this.frame);
  }
}
function request(page, options = {}) {
  const result = {responses: 0, bodies: 0};
  const response = {
    status: () => options.status ?? 200,
    url: () => options.url ?? endpoint,
    json: async () => {
      result.bodies++;
      if (options.error) throw options.error;
      return options.body ?? {state: 'absent', canWrite: false};
    },
  };
  result.request = {
    frame: () => options.frame ?? page.mainFrame(),
    method: () => options.method ?? 'GET',
    url: response.url,
    response: async () => {
      result.responses++;
      return options.noResponse ? null : response;
    },
  };
  result.response = response;
  return result;
}
function clean(page) {
  assert.equal(page.listenerCount('request'), 0);
  assert.equal(page.listenerCount('framenavigated'), 0);
  assert.equal(timers.size, 0);
}
const safePath = value => new URL(value).pathname;
"""


@unittest.skipUnless(NODE, "Node is required for viewer harness regressions")
class ViewerBrowserMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / "tests/splunk/viewer-browser.mjs").read_text()
        # Evaluate the actual dependency-free observer without starting the
        # credentialed top-level qualification browser.
        cls.helper = source.split("async function documentMetadata(", 1)[1].split(
            "\nconst BASE =", 1
        )[0]
        cls.helper = "async function documentMetadata(" + cls.helper

    def run_node(self, scenario):
        result = subprocess.run(
            [NODE, "--input-type=module"],
            input=FIXTURE + self.helper + scenario,
            text=True,
            capture_output=True,
            cwd=ROOT,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_outgoing_document_response_cannot_supply_current_metadata(self):
        self.run_node(r"""
const page = new Page();
const outgoing = request(page, {error: new Error('No resource with given identifier found')});
const early = request(page);
const current = request(page);
const [, metadata] = await documentMetadata(page, target, paths, safePath, async () => {
  // The previous page starts another health request before navigation commits.
  page.emit('request', early.request);
  page.commit();
  // Its late headers arrive after the commit. A response-only waiter matches it.
  page.emit('response', outgoing.response);
  // The new document's earliest request fires in the same synchronous turn.
  page.emit('request', current.request);
  return {status: 200};
});
assert.equal(outgoing.bodies, 0);
assert.equal(early.responses, 0);
assert.equal(current.bodies, 1);
assert.deepEqual(metadata[0].snapshot, {state: 'absent', canWrite: false});
clean(page);
""")

    def test_only_exact_get_target_in_main_document_is_accepted(self):
        self.run_node(r"""
const page = new Page();
const ignored = [
  request(page, {method: 'POST'}),
  request(page, {url: endpoint.replace('127.0.0.1', 'localhost')}),
  request(page, {url: endpoint.replace('deployment-settings?', 'deployment-settings-other?')}),
  request(page, {frame: {url: () => target}}),
];
const current = request(page, {status: 403, body: {error: 'denied'}});
const [, metadata] = await documentMetadata(page, target, paths, safePath, async () => {
  page.commit();
  for (const item of ignored) page.emit('request', item.request);
  page.emit('request', current.request);
});
for (const item of ignored) assert.equal(item.responses, 0);
// Preserve errors verbatim for the caller's existing status/body assertions.
assert.equal(metadata[0].status, 403);
assert.deepEqual(metadata[0].snapshot, {error: 'denied'});
clean(page);
""")

    def test_current_body_failure_propagates_without_retry(self):
        self.run_node(r"""
for (const error of [new SyntaxError('invalid JSON'), new Error('No resource with given identifier found')]) {
  const page = new Page();
  const current = request(page, {error});
  const later = request(page);
  await assert.rejects(documentMetadata(page, target, paths, safePath, async () => {
    page.commit();
    page.emit('request', current.request);
    page.emit('request', later.request);
  }), failure => failure === error);
  assert.equal(current.bodies, 1);
  assert.equal(later.responses, 0);
  clean(page);
}
""")

    def test_body_is_consumed_before_observation_releases_document(self):
        self.run_node(r"""
const page = new Page();
const current = request(page);
let releaseBody;
current.response.json = () => new Promise(resolve => { releaseBody = resolve; });
let settled = false;
const observation = documentMetadata(page, target, paths, safePath, async () => {
  page.commit();
  page.emit('request', current.request);
  return {status: 200};
}).then(result => { settled = true; return result; });
await new Promise(resolve => setImmediate(resolve));
assert.equal(settled, false);
assert.equal(page.listenerCount('framenavigated'), 1);
releaseBody({state: 'absent', canWrite: false});
const [, metadata] = await observation;
assert.equal(metadata[0].snapshot.state, 'absent');
clean(page);
""")

    def test_navigation_failure_timeout_and_missing_response_clean_up(self):
        self.run_node(r"""
for (const mode of ['navigate', 'timeout', 'missing', 'replaced']) {
  const page = new Page();
  await assert.rejects(documentMetadata(page, target, paths, safePath, async () => {
    if (mode === 'navigate') throw new Error('navigation failed');
    page.commit();
    if (mode === 'missing') page.emit('request', request(page, {noResponse: true}).request);
    if (mode === 'replaced') page.commit(target.replace('data_health', 'help'));
  }, 5), /navigation failed|timed out|has no response|navigated before completion/);
  clean(page);
}
""")
