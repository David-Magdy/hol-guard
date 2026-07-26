from __future__ import annotations

HOOK_METRIC_LABEL_MAX_CHARS = 80
HOOK_METRIC_BUCKET_LIMIT = 32
HOOK_METRIC_UNKNOWN = "unknown"


def increment_bounded_metric(counts: dict[str, int], value: object) -> None:
    label = (
        value
        if isinstance(value, str) and len(value) <= HOOK_METRIC_LABEL_MAX_CHARS and value.isidentifier()
        else HOOK_METRIC_UNKNOWN
    )
    if label not in counts:
        reserved_unknown_bucket = 0 if HOOK_METRIC_UNKNOWN in counts else 1
        if len(counts) >= HOOK_METRIC_BUCKET_LIMIT - reserved_unknown_bucket:
            label = HOOK_METRIC_UNKNOWN
    counts[label] = counts.get(label, 0) + 1


__all__ = [
    "HOOK_METRIC_BUCKET_LIMIT",
    "HOOK_METRIC_LABEL_MAX_CHARS",
    "HOOK_METRIC_UNKNOWN",
    "increment_bounded_metric",
]
