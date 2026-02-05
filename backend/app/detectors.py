from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional, Tuple


@dataclass
class DetectedLogType:
    name: str
    confidence: float
    sample: str


def _confidence(match_count: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return min(1.0, match_count / total)


# Common log patterns
SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>[^:]+):\s+(?P<msg>.*)$"
)
ISO_TS_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
NGINX_RE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+\"(?P<method>\S+)\s+(?P<path>[^\s]+)\s+\S+\"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)(?:\s+\"(?P<ref>[^\"]*)\"\s+\"(?P<ua>[^\"]*)\")?.*$"
)
APACHE_COMBINED_RE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+\"(?P<method>\S+)\s+(?P<path>[^\s]+)\s+\S+\"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)\s+\"(?P<ref>[^\"]*)\"\s+\"(?P<ua>[^\"]*)\".*$"
)
WINDOWS_EVENT_RE = re.compile(
    r"^\s*(?P<level>Information|Warning|Error|Critical)\s+\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+(?P<source>.+?)\s+Event\s+ID\s+(?P<id>\d+)\s+.*$",
    re.IGNORECASE,
)

LEVEL_RE = re.compile(r"\b(INFO|WARN|WARNING|ERROR|CRITICAL|FATAL|DEBUG|TRACE)\b", re.IGNORECASE)


def detect_log_types(lines: Iterable[str], max_lines: int = 200) -> List[DetectedLogType]:
    sample_lines = [line for i, line in enumerate(lines) if i < max_lines and line.strip()]
    total = len(sample_lines)
    if total == 0:
        return []

    syslog_matches = sum(1 for line in sample_lines if SYSLOG_RE.match(line))
    nginx_matches = sum(1 for line in sample_lines if NGINX_RE.match(line))
    apache_matches = sum(1 for line in sample_lines if APACHE_COMBINED_RE.match(line))
    windows_matches = sum(1 for line in sample_lines if WINDOWS_EVENT_RE.match(line))
    iso_ts_matches = sum(1 for line in sample_lines if ISO_TS_RE.match(line))

    candidates = [
        ("syslog", syslog_matches),
        ("nginx_access", nginx_matches),
        ("apache_access", apache_matches),
        ("windows_event", windows_matches),
        ("iso_timestamped", iso_ts_matches),
    ]

    detected: List[DetectedLogType] = []
    for name, count in candidates:
        if count == 0:
            continue
        detected.append(
            DetectedLogType(name=name, confidence=_confidence(count, total), sample=_sample_for(name, sample_lines))
        )

    detected.sort(key=lambda d: d.confidence, reverse=True)
    return detected


def _sample_for(name: str, lines: List[str]) -> str:
    matcher_map = {
        "syslog": SYSLOG_RE,
        "nginx_access": NGINX_RE,
        "apache_access": APACHE_COMBINED_RE,
        "windows_event": WINDOWS_EVENT_RE,
        "iso_timestamped": ISO_TS_RE,
    }
    matcher = matcher_map.get(name)
    if not matcher:
        return lines[0] if lines else ""
    for line in lines:
        if matcher.match(line):
            return line
    return lines[0] if lines else ""


def extract_levels(lines: Iterable[str]) -> List[str]:
    levels: List[str] = []
    for line in lines:
        match = LEVEL_RE.search(line)
        if match:
            levels.append(match.group(1).upper())
    return levels


def extract_timestamps(lines: Iterable[str], max_lines: int = 200) -> List[datetime]:
    timestamps: List[datetime] = []
    for i, line in enumerate(lines):
        if i >= max_lines:
            break
        iso_match = ISO_TS_RE.match(line)
        if iso_match:
            ts = iso_match.group("ts")
            try:
                timestamps.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
            except ValueError:
                continue
    return timestamps
