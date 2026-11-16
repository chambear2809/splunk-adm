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
grant any recipient permission. Shared-case controls now use an authenticated notes-only endpoint backed by the
SQLite case engine. This is separate from the portable editor: notes are not
automatically copied. The endpoint ships disabled and cannot store graph captures
or attachments without a source validator. Retry IDs and submitted payloads stay
in memory while a write outcome is unknown; leaving the workspace loses that
retry state. No case text is persisted in browser storage.
