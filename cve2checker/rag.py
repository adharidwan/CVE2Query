"""SQLite-backed retrieval index for Phase 0 RAG documents."""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable

_TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)

_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS documents (
        collection TEXT NOT NULL,
        id TEXT NOT NULL,
        title TEXT NOT NULL,
        text TEXT NOT NULL,
        metadata TEXT NOT NULL,
        PRIMARY KEY (collection, id)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS documents_collection_idx
    ON documents (collection)
    """,
)

_FTS_SCHEMA_STATEMENT = """
CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
    collection UNINDEXED,
    id UNINDEXED,
    title,
    text,
    tokenize = 'unicode61'
)
"""


class RagError(Exception):
    """An invalid retrieval index operation or document."""


class RagIndex:
    """A persistent, collection-scoped document index backed by SQLite."""

    def __init__(self, path: str | Path):
        self._path = str(path)
        Path(self._path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self._fts_enabled = False

        connection = self._connect()
        try:
            with connection:
                for statement in _SCHEMA_STATEMENTS:
                    connection.execute(statement)

            try:
                with connection:
                    connection.execute(_FTS_SCHEMA_STATEMENT)
                self._fts_enabled = True
            except sqlite3.OperationalError:
                self._fts_enabled = False
        finally:
            connection.close()

    def add_documents(self, collection: str, documents: Iterable[dict]) -> int:
        _validate_collection(collection)
        try:
            iterator = iter(documents)
        except TypeError as exc:
            raise RagError("documents must be an iterable of mappings") from exc

        connection = self._connect()
        count = 0
        try:
            with connection:
                for document in iterator:
                    doc_id, title, text, metadata_json = _normalise_document(document)
                    connection.execute(
                        """
                        INSERT INTO documents (collection, id, title, text, metadata)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(collection, id) DO UPDATE SET
                            title = excluded.title,
                            text = excluded.text,
                            metadata = excluded.metadata
                        """,
                        (collection, doc_id, title, text, metadata_json),
                    )
                    if self._fts_enabled:
                        connection.execute(
                            """
                            DELETE FROM documents_fts
                            WHERE collection = ? AND id = ?
                            """,
                            (collection, doc_id),
                        )
                        connection.execute(
                            """
                            INSERT INTO documents_fts (collection, id, title, text)
                            VALUES (?, ?, ?, ?)
                            """,
                            (collection, doc_id, title, text),
                        )
                    count += 1
        finally:
            connection.close()
        return count

    def search(self, collection: str, query: str, limit: int = 5) -> list[dict]:
        _validate_collection(collection)
        _validate_query(query)
        _validate_limit(limit)

        terms = _query_terms(query)
        if not terms:
            return []

        if not self._fts_enabled:
            return self._search_like(collection, terms, limit)

        expression = " OR ".join(f'"{term}"' for term in terms)
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT d.id, d.title, d.text, d.metadata,
                       bm25(documents_fts) AS rank
                FROM documents_fts
                JOIN documents AS d
                  ON d.collection = documents_fts.collection
                 AND d.id = documents_fts.id
                WHERE documents_fts.collection = ?
                  AND documents_fts MATCH ?
                ORDER BY rank ASC, d.id ASC
                LIMIT ?
                """,
                (collection, expression, limit),
            ).fetchall()
        finally:
            connection.close()

        return [_row_to_document(row, score=-float(row[4])) for row in rows]

    def get(
        self,
        collection: str,
        ids: list[str] | None = None,
        where: dict | None = None,
        limit: int = 10,
    ) -> list[dict]:
        _validate_collection(collection)
        _validate_limit(limit)
        if ids is not None:
            if not isinstance(ids, (list, tuple)):
                raise RagError("ids must be a list of strings or None")
            if any(not isinstance(doc_id, str) or not doc_id for doc_id in ids):
                raise RagError("ids must contain only non-empty strings")
            if not ids:
                return []
        if where is not None and not isinstance(where, dict):
            raise RagError("where must be a mapping or None")

        statement = (
            "SELECT id, title, text, metadata FROM documents WHERE collection = ?"
        )
        parameters: list[Any] = [collection]
        if ids is not None:
            placeholders = ", ".join("?" for _ in ids)
            statement += f" AND id IN ({placeholders})"
            parameters.extend(ids)
        statement += " ORDER BY id ASC"

        connection = self._connect()
        try:
            rows = connection.execute(statement, parameters).fetchall()
        finally:
            connection.close()

        if where:
            filtered_rows = []
            for row in rows:
                metadata = json.loads(row[3])
                if all(
                    key in metadata and metadata[key] == value
                    for key, value in where.items()
                ):
                    filtered_rows.append(row)
            rows = filtered_rows

        return [_row_to_document(row) for row in rows[:limit]]

    def collections(self) -> list[str]:
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT DISTINCT collection
                FROM documents
                ORDER BY collection ASC
                """
            ).fetchall()
        finally:
            connection.close()
        return [row[0] for row in rows]

    def _search_like(self, collection: str, terms: list[str], limit: int) -> list[dict]:
        clauses = " OR ".join(
            "(title LIKE ? ESCAPE '\\' OR text LIKE ? ESCAPE '\\')" for _ in terms
        )
        patterns: list[str] = []
        for term in terms:
            escaped = (
                term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            )
            patterns.extend((f"%{escaped}%", f"%{escaped}%"))

        connection = self._connect()
        try:
            rows = connection.execute(
                f"""
                SELECT id, title, text, metadata
                FROM documents
                WHERE collection = ? AND ({clauses})
                """,
                (collection, *patterns),
            ).fetchall()
        finally:
            connection.close()

        lowered_terms = [term.lower() for term in terms]
        lowered_query = " ".join(lowered_terms)
        results: list[dict] = []
        for row in rows:
            title = row[1].lower()
            text = row[2].lower()
            score = float(
                sum(title.count(term) for term in lowered_terms) * 2
                + sum(text.count(term) for term in lowered_terms)
            )
            if lowered_query in title:
                score += 5.0
            elif lowered_query in text:
                score += 2.0
            if score > 0:
                results.append(_row_to_document(row, score=score))

        results.sort(key=lambda document: (-document["score"], document["id"]))
        return results[:limit]

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path, timeout=30.0)


def _validate_collection(collection: Any) -> str:
    if not isinstance(collection, str) or not collection.strip():
        raise RagError("collection must be a non-empty string")
    return collection


def _validate_query(query: Any) -> str:
    if not isinstance(query, str) or not query.strip():
        raise RagError("query must be a non-empty string")
    return query


def _validate_limit(limit: Any) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise RagError("limit must be a positive integer")
    return limit


def _normalise_document(document: Any) -> tuple[str, str, str, str]:
    if not isinstance(document, dict):
        raise RagError("each document must be a mapping")

    doc_id = document.get("id")
    title = document.get("title")
    text = document.get("text")
    metadata = document.get("metadata")

    if not isinstance(doc_id, str) or not doc_id.strip():
        raise RagError("document id must be a non-empty string")
    if not isinstance(title, str):
        raise RagError(f"document {doc_id!r} title must be a string")
    if not isinstance(text, str):
        raise RagError(f"document {doc_id!r} text must be a string")
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, dict):
        raise RagError(f"document {doc_id!r} metadata must be a mapping or None")

    try:
        metadata_json = json.dumps(
            metadata, separators=(",", ":"), sort_keys=True, ensure_ascii=False
        )
    except (TypeError, ValueError) as exc:
        raise RagError(
            f"document {doc_id!r} metadata is not JSON serializable"
        ) from exc

    return doc_id, title, text, metadata_json


def _query_terms(query: str) -> list[str]:
    return _TOKEN_RE.findall(query)


def _row_to_document(row: tuple, score: float | None = None) -> dict:
    document = {
        "id": row[0],
        "title": row[1],
        "text": row[2],
        "metadata": json.loads(row[3]),
    }
    if score is not None:
        document["score"] = score
    return document
