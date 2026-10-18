"""Retrieve curated local security notes for AI explanations."""

from __future__ import annotations

import json
import os
from fnmatch import fnmatchcase
from functools import lru_cache
from pathlib import Path
from typing import Any

DEFAULT_KNOWLEDGE_FILE = Path(__file__).resolve().parent.parent / "knowledge" / "security_notes.json"
MAX_CONTEXT_CHARS = 6_000
TRUNCATION_MARK = " […]"
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def knowledge_file() -> Path:
    """Resolve the notes file; AAOS_KNOWLEDGE_FILE lets a lab keep its own curated notes."""
    override = os.getenv("AAOS_KNOWLEDGE_FILE", "").strip()
    return Path(override) if override else DEFAULT_KNOWLEDGE_FILE


@lru_cache(maxsize=1)
def _load_documents() -> tuple[dict[str, Any], ...]:
    """Load the local knowledge file on first retrieval and cache it for this process."""
    try:
        documents: Any = json.loads(knowledge_file().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ()
    if not isinstance(documents, list):
        return ()
    return tuple(
        document for document in documents
        if isinstance(document, dict)
        and isinstance(document.get("content"), str)
        and isinstance(document.get("rule_ids", []), list)
    )


def reload_knowledge_base() -> int:
    """Drop the cached notes so edits to the file apply without a restart; returns the new count."""
    _load_documents.cache_clear()
    return len(_load_documents())


def _rule_patterns(document: dict[str, Any]) -> list[str]:
    return [str(pattern) for pattern in document.get("rule_ids", []) if isinstance(pattern, str)]


def _is_general(document: dict[str, Any]) -> bool:
    return "*" in _rule_patterns(document)


def _matching_rule_ids(document: dict[str, Any], rule_ids: set[str]) -> set[str]:
    """Match exact IDs and glob patterns such as ANDROID-PERM-* or SEMGREP-*."""
    matched: set[str] = set()
    for pattern in _rule_patterns(document):
        if pattern == "*":
            continue
        if "*" in pattern or "?" in pattern:
            matched.update(rule_id for rule_id in rule_ids if fnmatchcase(rule_id, pattern))
        elif pattern in rule_ids:
            matched.add(pattern)
    return matched


def notes_for_rule(rule_id: str) -> list[dict[str, Any]]:
    """Return the specific (non-general) notes that apply to one rule ID."""
    return [
        document for document in _load_documents()
        if _matching_rule_ids(document, {rule_id})
    ]


def retrieve_context(findings: list[dict[str, str]]) -> tuple[str, list[dict[str, str]]]:
    """Return a bounded context string and source metadata relevant to the findings.

    General notes come first, then specific notes ranked by the most severe matching finding,
    so high-impact guidance survives when the character budget is tight.
    """
    rule_ids = {str(finding.get("rule_id", "")) for finding in findings if finding.get("rule_id")}
    best_severity: dict[str, int] = {}
    for finding in findings:
        rule_id = str(finding.get("rule_id", ""))
        rank = SEVERITY_RANK.get(str(finding.get("severity", "info")), len(SEVERITY_RANK))
        best_severity[rule_id] = min(rank, best_severity.get(rule_id, rank))

    general: list[dict[str, Any]] = []
    ranked: list[tuple[int, int, int, dict[str, Any]]] = []
    for position, document in enumerate(_load_documents()):
        if _is_general(document):
            general.append(document)
            continue
        matched = _matching_rule_ids(document, rule_ids)
        if matched:
            severity = min(best_severity.get(rule_id, len(SEVERITY_RANK)) for rule_id in matched)
            ranked.append((severity, -len(matched), position, document))
    selected = general + [document for *_, document in sorted(ranked, key=lambda item: item[:3])]

    context_parts: list[str] = []
    sources: list[dict[str, str]] = []
    seen: set[str] = set()
    remaining = MAX_CONTEXT_CHARS
    for document in selected:
        source_id = str(document.get("id", "unknown"))
        if source_id in seen:
            continue
        title = str(document.get("title", source_id))
        tags = [
            str(tag) for key in ("masvs", "cwe")
            for tag in (document.get(key) if isinstance(document.get(key), list) else [])
        ]
        header = f"[{source_id}] {title}"
        if tags:
            header += f" ({', '.join(tags)})"
        section = f"{header}\n{document['content'].strip()}"
        if len(section) > remaining:
            if context_parts:
                break
            section = section[:max(remaining - len(TRUNCATION_MARK), 0)] + TRUNCATION_MARK
        context_parts.append(section)
        sources.append({"id": source_id, "title": title})
        seen.add(source_id)
        remaining -= len(section) + 2
        if remaining <= 0:
            break

    return "\n\n".join(context_parts), sources


def search_notes(query: str, limit: int = 10) -> list[dict[str, Any]]:
    """Case-insensitive keyword search over note IDs, titles, rule IDs and content."""
    terms = [term for term in query.lower().split() if term]
    if not terms:
        return []
    scored: list[tuple[int, int, dict[str, Any]]] = []
    for position, document in enumerate(_load_documents()):
        title = str(document.get("title", "")).lower()
        haystack = " ".join([
            str(document.get("id", "")), title, " ".join(_rule_patterns(document)), document["content"],
        ]).lower()
        if all(term in haystack for term in terms):
            # Title hits rank above body-only hits.
            score = sum(2 if term in title else 1 for term in terms)
            scored.append((-score, position, document))
    return [document for *_, document in sorted(scored, key=lambda item: item[:2])[:max(limit, 0)]]


def validate_knowledge_base(known_rule_ids: set[str] | None = None) -> list[str]:
    """Report structural problems in the notes file; an empty list means it is usable."""
    path = knowledge_file()
    try:
        documents: Any = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return [f"Could not read {path.name}: {exc.strerror or exc}"]
    except json.JSONDecodeError as exc:
        return [f"{path.name} is not valid JSON (line {exc.lineno})."]
    if not isinstance(documents, list):
        return [f"{path.name} must contain a list of notes."]

    problems: list[str] = []
    seen_ids: set[str] = set()
    for index, document in enumerate(documents):
        label = f"note #{index + 1}"
        if not isinstance(document, dict):
            problems.append(f"{label}: is not a JSON object.")
            continue
        note_id = document.get("id")
        if not isinstance(note_id, str) or not note_id.strip():
            problems.append(f"{label}: missing 'id'.")
        else:
            label = f"note '{note_id}'"
            if note_id in seen_ids:
                problems.append(f"{label}: duplicate id.")
            seen_ids.add(note_id)
        if not isinstance(document.get("title"), str) or not document["title"].strip():
            problems.append(f"{label}: missing 'title'.")
        content = document.get("content")
        if not isinstance(content, str) or not content.strip():
            problems.append(f"{label}: missing 'content'.")
        elif len(content) > MAX_CONTEXT_CHARS:
            problems.append(f"{label}: 'content' exceeds {MAX_CONTEXT_CHARS} characters and would be truncated.")
        for optional in ("masvs", "cwe", "references"):
            value = document.get(optional)
            if value is not None and (not isinstance(value, list) or not all(isinstance(item, str) for item in value)):
                problems.append(f"{label}: '{optional}' must be a list of strings.")
        for url in document.get("references") or []:
            if isinstance(url, str) and not url.startswith("https://"):
                problems.append(f"{label}: reference '{url[:60]}' must use https://.")
        rule_ids = document.get("rule_ids")
        if not isinstance(rule_ids, list) or not rule_ids or not all(isinstance(item, str) for item in rule_ids):
            problems.append(f"{label}: 'rule_ids' must be a non-empty list of strings.")
        elif known_rule_ids is not None:
            for pattern in rule_ids:
                if pattern == "*" or "*" in pattern or "?" in pattern:
                    continue
                if pattern not in known_rule_ids:
                    problems.append(f"{label}: unknown rule '{pattern}'.")
    return problems


def knowledge_base_status() -> dict[str, int | bool]:
    """Report whether the knowledge file has been loaded without triggering a load."""
    loaded = _load_documents.cache_info().currsize > 0
    return {
        "loaded": loaded,
        "document_count": len(_load_documents()) if loaded else 0,
    }
