from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Dict, List, Optional

from .detectors import detect_log_types, extract_levels
from .ollama_client import OllamaClient


@dataclass
class AnalysisConfig:
    chunk_size: int = 2000
    overlap: int = 200
    max_chunks: int = 8
    temperature: float = 0.2


def _chunk_text(text: str, chunk_size: int, overlap: int) -> List[str]:
    if chunk_size <= 0:
        return [text]
    chunks: List[str] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + chunk_size)
        chunks.append(text[start:end])
        if end == len(text):
            break
        start = end - overlap
        if start < 0:
            start = 0
    return chunks


def _basic_stats(lines: List[str]) -> Dict[str, int]:
    levels = extract_levels(lines)
    stats: Dict[str, int] = {
        "lines": len(lines),
        "errors": sum(1 for level in levels if level in {"ERROR", "CRITICAL", "FATAL"}),
        "warnings": sum(1 for level in levels if level in {"WARN", "WARNING"}),
    }
    return stats


def _fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:12]


def analyze_logs(text: str, log_type_hint: Optional[str] = None, mode: str = "standard") -> Dict[str, object]:
    lines = [line for line in text.splitlines() if line.strip()]
    detected = detect_log_types(lines)
    stats = _basic_stats(lines)

    if mode == "quick":
        config = AnalysisConfig(chunk_size=2500, overlap=200, max_chunks=3)
    elif mode == "deep":
        config = AnalysisConfig(chunk_size=1500, overlap=300, max_chunks=12, temperature=0.1)
    else:
        config = AnalysisConfig()

    chunks = _chunk_text(text, config.chunk_size, config.overlap)[: config.max_chunks]

    client = OllamaClient()

    system_prompt = (
        "You are a security log analysis assistant for a SIEM lab. "
        "Analyze logs for anomalies, errors, security events, and operational issues. "
        "Return concise bullet points with evidence (timestamps, IPs, users, event IDs)."
    )

    type_context = log_type_hint or (detected[0].name if detected else "unknown")
    stats_context = f"Total lines: {stats['lines']}. Errors: {stats['errors']}. Warnings: {stats['warnings']}."

    chunk_summaries: List[str] = []
    for idx, chunk in enumerate(chunks, start=1):
        messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": (
                    f"Log type: {type_context}\n"
                    f"Stats: {stats_context}\n"
                    f"Chunk {idx}/{len(chunks)}:\n{chunk}\n\n"
                    "Identify issues, anomalies, or suspicious patterns. "
                    "If you see likely causes, call them out with short reasoning."
                ),
            },
        ]
        summary = client.chat(messages, temperature=config.temperature)
        chunk_summaries.append(summary.strip())

    synthesis_messages = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": (
                f"Log type: {type_context}\n"
                f"Stats: {stats_context}\n"
                "Combine the chunk analyses into a single report with sections: \n"
                "1) High-priority findings\n2) Notable anomalies\n3) Operational issues\n4) Suggested next steps\n"
                "Chunk analyses:\n" + "\n\n".join(chunk_summaries)
            ),
        },
    ]

    final_report = client.chat(synthesis_messages, temperature=config.temperature)

    return {
        "id": _fingerprint(text),
        "mode": mode,
        "detected_types": [det.__dict__ for det in detected],
        "stats": stats,
        "chunk_count": len(chunks),
        "report": final_report.strip(),
        "chunk_summaries": chunk_summaries,
    }
