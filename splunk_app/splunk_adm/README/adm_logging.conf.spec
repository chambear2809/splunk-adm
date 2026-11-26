# Operator log for Application Atlas REST handlers and the recovery alert action.
# Events go to $SPLUNK_HOME/var/log/splunk/splunk_adm.log (index=_internal,
# sourcetype=adm:operator). See docs/operators/troubleshooting.md.
# Override only in local/adm_logging.conf.

[logging]

level = DEBUG|INFO|WARNING|ERROR|OFF
* Defaults to INFO, which records refused (4xx) and failed (5xx) requests.
* DEBUG also records successful requests. WARNING and ERROR record only
  failed requests. OFF records nothing.
* Unrecognized values fall back to INFO.
* Lines never contain request or response bodies, headers, session tokens,
  principals or exception messages at any level.
* Running handlers pick up a change within 30 seconds; no restart is needed.
