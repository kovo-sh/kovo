"""Kovo v4 zero-egress Python IAST hook for local-lab containers."""
import json
import os
import re
import sys
import time
import traceback

OUT_DIR = os.environ.get("KOVO_IAST_OUT_DIR", "/var/run/kovo-iast")
MAX_BYTES = 65536

_SECRET_PATTERNS = [
    re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?"),
    re.compile(r"\bBearer\s+[a-zA-Z0-9._~+/=-]{8,}", re.IGNORECASE),
    re.compile(r"\b(?:authorization|cookie|set-cookie)\s*:\s*[^\n\r]+", re.IGNORECASE),
]


def _scrub(text: str) -> str:
    out = str(text or "")
    for pat in _SECRET_PATTERNS:
        out = pat.sub("[redacted]", out)
    return out


def _safe_id(raw: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]", "_", str(raw or "trace"))[:96]
    return cleaned or "trace"


def emit_telemetry(trace_id: str, routes_hit=None, sink_events=None, exceptions=None, new_lines=1):
    try:
        os.makedirs(OUT_DIR, exist_ok=True)
        payload = {
            "traceId": _scrub(trace_id),
            "routesHit": [_scrub(r) for r in (routes_hit or [])][:32],
            "newLinesCovered": max(0, int(new_lines or 0)),
            "sinkEvents": [
                {k: _scrub(v)[:512] if isinstance(v, str) else v for k, v in ev.items()}
                for ev in (sink_events or [])[:32]
                if isinstance(ev, dict)
            ],
            "exceptions": [
                {k: _scrub(v)[:1024] if isinstance(v, str) else v for k, v in ex.items()}
                for ex in (exceptions or [])[:16]
                if isinstance(ex, dict)
            ],
            "ts": int(time.time() * 1000),
        }
        raw = json.dumps(payload).encode("utf-8")
        if len(raw) > MAX_BYTES:
            payload["sinkEvents"] = payload["sinkEvents"][:8]
            payload["exceptions"] = payload["exceptions"][:4]
            payload["truncated"] = True
            raw = json.dumps(payload).encode("utf-8")[:MAX_BYTES]
        path = os.path.join(OUT_DIR, f"{_safe_id(trace_id)}.json")
        with open(path, "wb") as fh:
            fh.write(raw)
    except Exception:
        pass


_orig_excepthook = sys.excepthook


def _kovo_excepthook(exc_type, exc_value, exc_tb):
    trace_id = os.environ.get("KOVO_CURRENT_TRACE_ID", f"py-exc-{int(time.time() * 1000)}")
    stack = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    emit_telemetry(
        trace_id,
        exceptions=[{"message": _scrub(str(exc_value))[:512], "stack": _scrub(stack)[:2048]}],
        new_lines=0,
    )
    _orig_excepthook(exc_type, exc_value, exc_tb)


sys.excepthook = _kovo_excepthook
