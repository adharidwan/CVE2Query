"""CVE Services API access and CVE v5 draft extraction."""

from __future__ import annotations

import json
import re
from typing import Any, Iterator
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

API_BASE_URL = "https://cveawg.mitre.org/api/cve"
_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")


class CVEError(Exception):
    """An invalid CVE identifier, record, or API operation."""


def validate_cve_id(cve_id: str) -> str:
    if not isinstance(cve_id, str) or _CVE_ID.fullmatch(cve_id) is None:
        raise CVEError(
            f"invalid CVE ID {cve_id!r}; expected CVE-YYYY-NNNN "
            "with at least four digits in NNNN"
        )
    return cve_id


def parse_record(raw_json: bytes | str, expected_cve_id: str | None = None) -> dict[str, Any]:
    """Parse and minimally validate a CVE v5 record."""
    if expected_cve_id is not None:
        validate_cve_id(expected_cve_id)

    try:
        record = json.loads(raw_json)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CVEError(f"record is not valid JSON: {exc}") from exc

    if not isinstance(record, dict) or record.get("dataType") != "CVE_RECORD":
        raise CVEError("response is not a CVE v5 record (expected dataType 'CVE_RECORD')")

    metadata = record.get("cveMetadata")
    if not isinstance(metadata, dict):
        raise CVEError("CVE v5 record is missing its cveMetadata object")

    record_id = metadata.get("cveId")
    if not isinstance(record_id, str) or _CVE_ID.fullmatch(record_id) is None:
        raise CVEError("CVE v5 record is missing a valid cveMetadata.cveId")
    if expected_cve_id is not None and record_id != expected_cve_id:
        raise CVEError(
            f"record CVE ID {record_id} does not match requested ID {expected_cve_id}"
        )

    if not isinstance(record.get("containers"), dict):
        raise CVEError("CVE v5 record is missing its containers object")
    return record


def fetch_record(cve_id: str, timeout: float = 20.0) -> tuple[dict[str, Any], bytes]:
    """Fetch a raw CVE Services API response and return it with its parsed record."""
    validate_cve_id(cve_id)
    url = f"{API_BASE_URL}/{cve_id}"
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "cve2checker/0.1",
        },
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            raw_json = response.read()
    except HTTPError as exc:
        if exc.code == 404:
            raise CVEError(f"CVE Services API has no record for {cve_id} (HTTP 404)") from exc
        raise CVEError(
            f"CVE Services API returned HTTP {exc.code} for {cve_id}: {exc.reason}"
        ) from exc
    except URLError as exc:
        raise CVEError(f"could not reach CVE Services API at {url}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise CVEError(f"timed out while contacting CVE Services API at {url}") from exc
    except OSError as exc:
        raise CVEError(f"could not read CVE Services API response from {url}: {exc}") from exc

    try:
        record = parse_record(raw_json, cve_id)
    except CVEError as exc:
        raise CVEError(f"CVE Services API returned an invalid record: {exc}") from exc
    return record, raw_json


def build_vulnerability_spec(cve_id: str, record: dict[str, Any]) -> dict[str, Any]:
    """Build an evidence-gated CodeQL vulnerability IR from CVE metadata."""
    validate_cve_id(cve_id)
    if not isinstance(record, dict):
        raise CVEError("cannot build a draft from a non-object CVE record")

    metadata = record.get("cveMetadata")
    if not isinstance(metadata, dict) or metadata.get("cveId") != cve_id:
        raise CVEError(f"CVE record does not match requested ID {cve_id}")

    containers = list(_iter_record_containers(record))
    descriptions = [
        description
        for container in containers
        for description in _dict_list(container.get("descriptions"))
        if isinstance(description.get("value"), str)
    ]
    english_description = next(
        (
            item["value"]
            for item in descriptions
            if isinstance(item.get("lang"), str)
            and item["lang"].lower().split("-", 1)[0] == "en"
        ),
        None,
    )
    description = english_description or (
        descriptions[0]["value"] if descriptions else None
    )

    cwe_ids: list[str] = []
    affected: list[dict[str, Any]] = []
    references: list[dict[str, Any]] = []
    for container in containers:
        for problem_type in _dict_list(container.get("problemTypes")):
            for item in _dict_list(problem_type.get("descriptions")):
                cwe_id = item.get("cweId")
                if isinstance(cwe_id, str) and cwe_id.strip() and cwe_id not in cwe_ids:
                    cwe_ids.append(cwe_id)

        for product in _dict_list(container.get("affected")):
            versions = product.get("versions")
            affected.append(
                {
                    "vendor": product.get("vendor"),
                    "product": product.get("product"),
                    "versions": versions if isinstance(versions, list) else [],
                }
            )

        references.extend(_dict_list(container.get("references")))

    return {
        "schema_version": "1.0",
        "cve_id": cve_id,
        "language": None,
        "status": "insufficient_evidence",
        "weakness": {"cwe_ids": cwe_ids},
        "root_cause": {
            "type": None,
            "sink": None,
            "unsafe_condition": None,
            "preconditions": [],
            "evidence": [],
        },
        "detection": {
            "query_language": "CodeQL",
            "approach": None,
            "sources": [],
            "sinks": [],
            "barriers": [],
            "requires_dataflow": None,
        },
        "evidence": {
            "cve_record": f"{API_BASE_URL}/{cve_id}",
            "description": description,
            "affected": affected,
            "references": references,
            "source_repository": None,
            "vulnerable_commit": None,
            "fix_commit": None,
            "source_files": [],
        },
        "generation_gate": {
            "decision": "blocked",
            "reasons": [
                "CVE metadata alone does not establish a source-level root cause.",
                "A public source repository and vulnerable/fixed code evidence are required before query generation.",
            ],
        },
    }


def iter_record_containers(record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield the CNA and ADP containers from a CVE v5 record."""
    return _iter_record_containers(record)


def _iter_record_containers(record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    containers = record.get("containers")
    if not isinstance(containers, dict):
        return

    cna = containers.get("cna")
    if isinstance(cna, dict):
        yield cna

    for adp in _dict_list(containers.get("adp")):
        yield adp


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]
