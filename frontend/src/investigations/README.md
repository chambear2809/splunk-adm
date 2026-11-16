# Portable investigation handoff

The incident workspace's Notes tab records detached graph captures and append-only
note revisions. The capture keeps absolute windows, snapshot identity, source
evidence, and coverage information. Later graph refreshes do not replace it.
Readable handoffs include notes, hypotheses, unresolved questions, demo labels,
and coverage cautions. Explicitly selecting full evidence exports a version 1
JSON package with the captured graphs. These packages can contain sensitive
source data and are separate from generic map export.

The open record lives in component memory. Closing the investigation discards it;
the UI says so and offers a download. Downloading does not save a shared case or
grant any recipient permission. The SQLite case engine is independent and still
needs an authenticated, entitlement-aware application adapter and browser client.
No browser storage, background upload, or privileged persistence is invoked here.
