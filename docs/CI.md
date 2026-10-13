# Continuous integration

The automatic GitHub Actions checks run on every push to `main` and every pull
request. They install Node 22.13 and run `npm run lint`, `npm test`, and
`npm run package`, then verify both generated release archives and their
checksums with `tools/check_release.py`. A separate Python job installs Ruff 0.13.2 and runs the
repository's documented checks over `tools/` and `tests/`, plus the standalone
Python unit tests and the upgrade metadata/ACL unit tests. A Chromium job runs
`npm run typecheck:browser` and `npm run test:browser` against the deterministic
mock-SDK harness. The full package-update and paced-ingestion checks remain
explicit local lab runs; see [upgrades](UPGRADES.md) and [continuous load](CONTINUOUS_LOAD.md).

The Splunk integration suite runs when `run_splunk_lab` is selected from the
Actions **Run workflow** form on the repository's default branch. After the runner
is provisioned, set repository variable `ADM_SPLUNK_LAB_ENABLED=true` to also run
it automatically on pushes to the default branch (the push trigger currently
targets `main`). It uses a dedicated self-hosted runner with all
of these labels: `self-hosted`, `linux`, `x64`, and `splunk-adm-lab`. Do not
attach general-purpose or shared runners: the job runs repository code beside
licensed Splunk and Cisco TA files and starts a Docker container.

Configure the repository variable `ADM_TA_ROOT` to an external, durable
directory on that runner. It must contain:

```text
<ADM_TA_ROOT>/packages/
```

The `packages/` directory must contain the three corresponding archives listed
in `research/package-manifest.json`. The workflow verifies their SHA-256 values
and safely extracts them into the checkout with `tools/prepare_ci_tas.py`; it
does not trust pre-extracted files from the runner.
It never stores these artifacts in GitHub or includes them in a build artifact.

The runner should be disposable between runs, have Python 3.12+ and Docker available to the
runner account, and keep its TA directory outside the checkout. Cleanup runs
with `if: always()` and removes the lab container, image, volumes, and generated
credentials. The workflow does not run this job for pull requests or untrusted
branches.

The manual `run_pipeline_rehearsals` option also starts the trusted lab job and
runs the mixed-source baseline followed by the real scheduler/downtime
rehearsal. They run sequentially after the integration suite, with a fresh app
install to remove test overrides. The lab job has a 70-minute overall budget
and always purges the container afterward. Available JSON reports are retained
as the `pipeline-rehearsal-evidence` artifact for 14 days, including failed runs.
These slower rehearsals are opt-in;
they do not run on pull requests. See [mixed-source load](MIXED_LOAD.md) and
[scheduler testing](SCHEDULER_TESTS.md).
