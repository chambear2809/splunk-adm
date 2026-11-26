"""Insert-only observer mapping. Stable keys match the documented KV upsert."""

import hashlib
import json
import re
from urllib.parse import urlsplit

from adm_kv_lib.ledger import Forbidden, Invalid, Unavailable, canonical
from adm_kv_lib.store import SplunkCollectionStore

KIND = re.compile(r"[a-z][a-z0-9._-]{0,63}\Z")
OBSERVER = re.compile(r"[a-z0-9][a-z0-9._:/@-]{0,253}\Z")
SCOPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}\Z")
CLUSTER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,253}\Z")
REALM = re.compile(r"[a-z][a-z0-9]{0,7}\Z")
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}\Z")
UNMAPPED = re.compile(r"(?i)^(unmapped|unknown|reserved)(:|$)")
COLLECTION = "adm_observer_scope"
MAPPING_LIMIT = 4096
MAX_BODY_BYTES = 32 * 1024
ORIGIN_FIELDS = frozenset(
    {"observability_origin", "controller_origin", "thousandeyes_origin"}
)
OPTIONAL_FIELDS = (
    "account_id",
    "region",
    "vpc_id",
    "organization_id",
    "realm",
    "apm_mms_id",
    "detector_ids",
    "controller_origin",
    "observability_origin",
    "te_account_group_id",
    "te_stream_account_id",
    "te_alert_account_id",
    "te_organization_id",
    "te_families",
    "te_bindings",
    "te_path_sources",
    "thousandeyes_origin",
)


def _https_origin(value, label):
    if not isinstance(value, str) or len(value) > 255:
        raise Invalid(label + " must be an HTTPS URL.")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise Invalid(label + " must be an HTTPS URL without credentials.")
    return value


def mapping_key(kind, observer):
    return hashlib.sha256(canonical([kind, observer]).encode()).hexdigest()


def _text(value, pattern, label, *, allow_empty=False):
    if value in (None, "") and allow_empty:
        return ""
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise Invalid("Invalid " + label + ".")
    return value


def validate_mapping(body):
    if not isinstance(body, dict):
        raise Invalid("Invalid observer mapping.")
    kind = _text(
        body.get("observer_kind", "").strip().lower()
        if isinstance(body.get("observer_kind"), str)
        else "",
        KIND,
        "observer kind",
    )
    observer = _text(
        body.get("observer", "").strip().lower()
        if isinstance(body.get("observer"), str)
        else "",
        OBSERVER,
        "observer",
    )
    scope = _text(body.get("scope"), SCOPE, "scope")
    if UNMAPPED.search(scope):
        raise Invalid("Mapped scopes cannot use a reserved unmapped identity.")
    cluster = body.get("cluster", "")
    if cluster not in (None, ""):
        cluster = _text(cluster, CLUSTER, "cluster")
    else:
        cluster = ""
    realm = body.get("realm")
    if realm not in (None, ""):
        _text(realm, REALM, "Observability realm")
    document = {
        "_key": mapping_key(kind, observer),
        "observer_kind": kind,
        "observer": observer,
        "scope": scope,
        "cluster": cluster,
        "mapping_status": "mapped",
    }
    for field in OPTIONAL_FIELDS:
        value = body.get(field)
        if value in (None, ""):
            continue
        if field == "realm":
            document[field] = realm
        elif field in ORIGIN_FIELDS:
            document[field] = _https_origin(value, field)
        else:
            document[field] = _text(value, TOKEN, field)
    return document


def _same_mapping(existing, document):
    fields = ("observer_kind", "observer", "scope", "cluster", *OPTIONAL_FIELDS)
    for field in fields:
        if (existing.get(field) or "") != (document.get(field) or ""):
            return False
    return True


def handle_request(request, token):
    method = request.get("method", "").upper()
    if method not in ("GET", "POST"):
        raise Invalid("Only GET and POST are supported.")
    store = SplunkCollectionStore(token, COLLECTION)
    if method == "GET":
        try:
            rows = store.scan(
                MAPPING_LIMIT + 1,
                fields="_key,observer_kind,observer,scope,cluster,mapping_status",
            )
        except TypeError:
            rows = store.scan(MAPPING_LIMIT + 1)
        if len(rows) > MAPPING_LIMIT:
            raise Unavailable(
                "Observer mapping history limit reached; writes are disabled."
            )
        return {
            "state": "configured" if rows else "absent",
            "mappings": [
                {
                    key: row.get(key)
                    for key in (
                        "_key",
                        "observer_kind",
                        "observer",
                        "scope",
                        "cluster",
                        "mapping_status",
                    )
                    if key in row
                }
                for row in rows
                if isinstance(row, dict)
            ],
            "recordCount": len(rows),
        }
    raw = request.get("payload", "")
    if isinstance(raw, dict):
        body = raw
        encoded = json.dumps(body, separators=(",", ":"), allow_nan=False)
        if len(encoded.encode()) > MAX_BODY_BYTES:
            raise Invalid("Observer mapping payload exceeds 32 KiB.")
    else:
        if not isinstance(raw, str) or not raw:
            raise Invalid("Invalid observer mapping.")
        if len(raw.encode()) > MAX_BODY_BYTES:
            raise Invalid("Observer mapping payload exceeds 32 KiB.")
        try:
            body = json.loads(raw)
        except ValueError as exc:
            raise Invalid("Invalid observer mapping.") from exc
    if not store.allows_write("admin_all_objects"):
        raise Forbidden(
            "Administrator permission is required to store observer mappings."
        )
    document = validate_mapping(body)
    try:
        store.insert(document)
    except Forbidden:
        raise
    except Exception as exc:
        if hasattr(store, "get"):
            existing_row = store.get(document["_key"])
            existing = [existing_row] if isinstance(existing_row, dict) else []
        else:
            existing = [
                row
                for row in store.scan(MAPPING_LIMIT + 1)
                if isinstance(row, dict) and row.get("_key") == document["_key"]
            ]
        if existing:
            if _same_mapping(existing[0], document):
                return {
                    "state": "configured",
                    "mapping": existing[0],
                    "idempotent": True,
                }
            raise Invalid(
                "Observer already mapped. Insert-only KV does not replace an existing mapping."
            ) from exc
        raise Unavailable("Observer mapping could not be stored.") from exc
    return {"state": "configured", "mapping": document, "idempotent": False}
