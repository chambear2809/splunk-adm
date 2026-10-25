# External optional integration toolkit

The `application-atlas-integrations-0.5.0.tar.gz` archive contains external
collection/delivery tools, processor contract artifacts and operator guides.
It is separate from `splunk_adm-0.5.0.tar.gz`. Installing the Splunk app does
not install these tools, dependencies, credentials, schedules or pipelines.
All new sources start unselected and unqualified.

Verify the supplied SHA-256 checksum, extract the archive into an
operator-controlled installation directory, and run commands from its
`application-atlas-integrations/` root. The qualified local runtime is Python
3.13 on Unix. Use a private virtual environment; do not install globally:

```sh
python3.13 -m venv .venv
.venv/bin/python -m pip install -r tools/requirements-o11y.txt
.venv/bin/python -m tools.export_o11y_health --help
.venv/bin/python -m tools.capture_o11y_health --help
.venv/bin/python -m tools.export_o11y_detector_events --help
.venv/bin/python -m tools.export_appdynamics --help
.venv/bin/python -m tools.import_appdynamics --help
.venv/bin/python -m tools.hec_delivery --help
.venv/bin/python -m tools.validate_processor_contract
```

Only the SignalFlow health exporter requires the pinned external
`signalflow-client-python==1.3.9` dependency. The Controller collector,
detector REST exporter, shared HEC sender and processor validator use the
Python standard library. The unpacked toolkit smoke test executes every
listed CLI and the actual processor contract validator outside the repository.
This verifies distribution/importability, not a connection to a source or a
processor runtime.

Follow the source guides before collecting or selecting evidence:

- [Historical health and scheduling](operators/o11y-health.md).
- [Product navigation and reciprocal APM data links](operators/o11y-navigation.md).
- [Configured detector event history](operators/o11y-detector-events.md).
- [AppDynamics current inventory and backend candidates](operators/appdynamics-evidence.md).
- [Edge Processor and Ingest Processor profiles](operators/ingest-processors.md).
- [Qualification matrix and external limits](OPTIONAL_INTEGRATIONS_QUALIFICATION.md).

Inject API and HEC credentials through the protected process environment from
the operator's secret manager. The guides identify exact environment variable
names and least-privilege source permissions. Do not put credential values in
commands, checked-in files, logs or browser settings. Keep finalized captures,
state and HEC spools in separate owner-only directories outside the
installation directory and every Git checkout. Configure TLS trust without
disabling certificate or hostname verification.

Collection and queueing do not deliver data. Run the common sender separately.
HTTP acceptance, Enterprise indexer acknowledgment where supported, and indexed
search readback remain separate facts. Retries can duplicate events; retain
source/capture/record identity and apply the source reader's replay rules.
A full spool stops acceptance and preserves undelivered captures. Resolve a
reported integrity/configuration failure before retrying; do not remove the
only valid source or edit checkpoints to skip records.

The processor validator checks versioned fixtures and semantic contracts. It
does not execute SPL2. Do not enable a processor profile until product-side
preview, configured fallback/destination behavior, and indexed readback pass
for the exact deployed product/version. Real Observability organizations,
Controller deployments and processor runtimes remain external qualification
requirements.

Rollback stops the external schedules/sender, preserves pending state and
captures, unselects the affected Atlas source, and clears its qualification
flag. Indexed observations remain under the operator's retention policy.
