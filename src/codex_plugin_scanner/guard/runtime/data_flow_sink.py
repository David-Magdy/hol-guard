"""Shared user-facing classification for runtime data-flow sinks."""

from __future__ import annotations

from .signals import RiskSignalV2


def data_flow_sink_type(signals: tuple[RiskSignalV2, ...]) -> str:
    """Return the stable sink label for a set of risk signals."""

    signal_ids = {signal.signal_id for signal in signals}
    if any(signal.category == "network" for signal in signals):
        return "network host"
    if "data-flow:clipboard-secret" in signal_ids:
        return "clipboard"
    if "data-flow:world-readable-temp-secret" in signal_ids:
        return "world-readable temp file"
    if "data-flow:git-remote-token" in signal_ids:
        return "git remote configuration"
    return "external sink"
