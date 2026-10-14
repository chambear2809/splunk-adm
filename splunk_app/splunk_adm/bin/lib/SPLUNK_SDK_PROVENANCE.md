# Vendored Splunk Python SDK

This directory contains the `splunklib` package from the official Splunk SDK
for Python release 2.1.1.

- Source: https://github.com/splunk/splunk-sdk-python/releases/tag/2.1.1
- Source archive: `https://github.com/splunk/splunk-sdk-python/archive/refs/tags/2.1.1.tar.gz`
- Archive SHA-256: `6a267b199a8099df6ab9cf198e1b72e6200a5de6baa551e4859f2ca426d08685`
- Vendored path: `bin/lib/splunklib`
- License: `bin/lib/SPLUNK_SDK_LICENSE.txt` (the unmodified Apache License 2.0
  file shipped in the same source archive)

To reproduce, download the source archive, verify the SHA-256 above, extract
the `splunklib/` directory from the archive root, and replace this directory.
Copy the archive root `LICENSE` to `bin/lib/SPLUNK_SDK_LICENSE.txt`.
The action does not install or download dependencies at runtime. It uses the
local Splunk management REST API over the supplied session context.
