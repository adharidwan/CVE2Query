import tempfile
import unittest
from pathlib import Path

from cve2checker.rag import RagError, RagIndex


class RagIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self.root = Path(self._temporary_directory.name)
        self.index_path = self.root / "nested" / "rag.sqlite3"
        self.index = RagIndex(self.index_path)

    def test_add_and_search_returns_most_relevant_document(self) -> None:
        added = self.index.add_documents(
            "advisories",
            [
                {
                    "id": "sql",
                    "title": "SQL injection in login",
                    "text": "Untrusted input reaches a database query.",
                    "metadata": {"severity": "high"},
                },
                {
                    "id": "xss",
                    "title": "Cross-site scripting",
                    "text": "Reflected HTML injection in search.",
                    "metadata": None,
                },
                {
                    "id": "buffer",
                    "title": "Buffer overflow",
                    "text": "A stack buffer overflow in the parser.",
                    "metadata": {},
                },
            ],
        )

        self.assertEqual(added, 3)
        self.assertTrue(self.index_path.exists())

        results = self.index.search("advisories", "buffer overflow")

        self.assertTrue(results)
        self.assertEqual(results[0]["id"], "buffer")
        self.assertEqual(results[0]["metadata"], {})
        self.assertIsInstance(results[0]["score"], (int, float))
        self.assertGreater(results[0]["score"], 0)
        self.assertEqual(
            set(results[0]), {"id", "title", "text", "metadata", "score"}
        )

    def test_get_by_ids_and_metadata_where(self) -> None:
        self.index.add_documents(
            "cves",
            [
                {
                    "id": "a",
                    "title": "Alpha",
                    "text": "First advisory.",
                    "metadata": {"severity": "high", "kind": "cve"},
                },
                {
                    "id": "b",
                    "title": "Beta",
                    "text": "Second advisory.",
                    "metadata": {"severity": "low", "kind": "cve"},
                },
                {
                    "id": "c",
                    "title": "Gamma",
                    "text": "Third advisory.",
                    "metadata": {"severity": "high", "kind": "patch"},
                },
                {
                    "id": "d",
                    "title": "Delta",
                    "text": "Fourth advisory.",
                    "metadata": {"severity": "high", "kind": "cve", "year": 2024},
                },
            ],
        )

        by_ids = self.index.get("cves", ids=["c", "a"])
        self.assertEqual([document["id"] for document in by_ids], ["a", "c"])
        for document in by_ids:
            self.assertEqual(
                set(document), {"id", "title", "text", "metadata"}
            )

        high = self.index.get("cves", where={"severity": "high"})
        self.assertEqual({document["id"] for document in high}, {"a", "c", "d"})

        combined = self.index.get(
            "cves",
            ids=["a", "b", "c", "d"],
            where={"severity": "high", "kind": "cve"},
        )
        self.assertEqual({document["id"] for document in combined}, {"a", "d"})

        numeric = self.index.get("cves", where={"year": 2024})
        self.assertEqual([document["id"] for document in numeric], ["d"])

        self.assertEqual(self.index.get("cves", ids=["missing"]), [])
        self.assertEqual(self.index.get("cves", where={"severity": "critical"}), [])

    def test_collection_isolation_and_collections_listing(self) -> None:
        self.index.add_documents(
            "alpha",
            [
                {
                    "id": "shared",
                    "title": "Alpha document",
                    "text": "Contains alphaonly content.",
                    "metadata": {"collection": "alpha"},
                }
            ],
        )
        self.index.add_documents(
            "beta",
            [
                {
                    "id": "shared",
                    "title": "Beta document",
                    "text": "Contains betaonly content.",
                    "metadata": {"collection": "beta"},
                }
            ],
        )

        alpha_results = self.index.search("alpha", "betaonly")
        beta_results = self.index.search("beta", "betaonly")
        self.assertEqual(alpha_results, [])
        self.assertEqual([document["id"] for document in beta_results], ["shared"])

        alpha_document = self.index.get("alpha", ids=["shared"])
        self.assertEqual(len(alpha_document), 1)
        self.assertEqual(alpha_document[0]["title"], "Alpha document")
        self.assertEqual(alpha_document[0]["metadata"], {"collection": "alpha"})

        self.assertEqual(self.index.collections(), ["alpha", "beta"])

        self.index.add_documents(
            "gamma",
            [{"id": "one", "title": "Gamma", "text": "Gamma data.", "metadata": None}],
        )
        self.assertEqual(self.index.collections(), ["alpha", "beta", "gamma"])

    def test_replacement_of_existing_id(self) -> None:
        self.index.add_documents(
            "patterns",
            [
                {
                    "id": "cve-1",
                    "title": "Original title",
                    "text": "alphaonly content",
                    "metadata": {"version": 1},
                }
            ],
        )

        replaced = self.index.add_documents(
            "patterns",
            [
                {
                    "id": "cve-1",
                    "title": "Updated title",
                    "text": "betaonly content",
                    "metadata": {"version": 2},
                }
            ],
        )

        self.assertEqual(replaced, 1)
        documents = self.index.get("patterns", ids=["cve-1"])
        self.assertEqual(len(documents), 1)
        self.assertEqual(documents[0]["title"], "Updated title")
        self.assertEqual(documents[0]["text"], "betaonly content")
        self.assertEqual(documents[0]["metadata"], {"version": 2})

        old_results = self.index.search("patterns", "alphaonly")
        self.assertNotIn("cve-1", [document["id"] for document in old_results])
        new_results = self.index.search("patterns", "betaonly")
        self.assertEqual([document["id"] for document in new_results], ["cve-1"])

    def test_validation_errors(self) -> None:
        for collection in ("", "   ", None, 42):
            with self.subTest(collection=collection):
                with self.assertRaises(RagError):
                    self.index.add_documents(collection, [])
                with self.assertRaises(RagError):
                    self.index.search(collection, "query")
                with self.assertRaises(RagError):
                    self.index.get(collection)

        for query in ("", "   ", None, 42):
            with self.subTest(query=query), self.assertRaises(RagError):
                self.index.search("valid", query)

        for limit in (0, -1, 1.5, True, "5"):
            with self.subTest(limit=limit):
                with self.assertRaises(RagError):
                    self.index.search("valid", "query", limit=limit)
                with self.assertRaises(RagError):
                    self.index.get("valid", limit=limit)

        with self.assertRaises(RagError):
            self.index.get("valid", ids="not-a-list")
        with self.assertRaises(RagError):
            self.index.get("valid", ids=[""])
        with self.assertRaises(RagError):
            self.index.get("valid", where=["severity"])

        invalid_documents = (
            "not-a-mapping",
            {"id": "", "title": "Title", "text": "Text"},
            {"id": "x", "title": 1, "text": "Text"},
            {"id": "x", "title": "Title", "text": None},
            {"id": "x", "title": "Title", "text": "Text", "metadata": []},
        )
        for document in invalid_documents:
            with self.subTest(document=document), self.assertRaises(RagError):
                self.index.add_documents("valid", [document])

    def test_failed_batch_rolls_back(self) -> None:
        with self.assertRaises(RagError):
            self.index.add_documents(
                "atomic",
                [
                    {"id": "good", "title": "Good", "text": "Good text."},
                    {"id": "", "title": "Bad", "text": "Bad text."},
                ],
            )

        self.assertEqual(self.index.get("atomic", ids=["good"]), [])
        self.assertEqual(self.index.collections(), [])

    def test_search_limit(self) -> None:
        self.index.add_documents(
            "limited",
            [
                {
                    "id": f"doc{number}",
                    "title": f"Document {number}",
                    "text": "A shared vulnerability token.",
                    "metadata": {"number": number},
                }
                for number in range(1, 6)
            ],
        )

        self.assertEqual(
            [document["id"] for document in self.index.search("limited", "shared", limit=2)],
            ["doc1", "doc2"],
        )
        self.assertEqual(
            len(self.index.search("limited", "shared", limit=1)), 1
        )
        self.assertEqual(
            len(self.index.search("limited", "shared", limit=10)), 5
        )

    def test_empty_index(self) -> None:
        self.assertEqual(self.index.search("missing", "anything"), [])
        self.assertEqual(self.index.get("missing"), [])
        self.assertEqual(self.index.get("missing", ids=["one"]), [])
        self.assertEqual(self.index.get("missing", where={"severity": "high"}), [])
        self.assertEqual(self.index.collections(), [])
        self.assertEqual(self.index.add_documents("missing", []), 0)

    def test_like_fallback_search(self) -> None:
        self.index.add_documents(
            "fallback",
            [
                {
                    "id": "relevant",
                    "title": "Remote code execution",
                    "text": "The parser allows an attacker to run code.",
                    "metadata": {},
                },
                {
                    "id": "other",
                    "title": "Denial of service",
                    "text": "The parser consumes all available memory.",
                    "metadata": {},
                },
            ],
        )
        self.index._fts_enabled = False

        results = self.index.search("fallback", "code execution")

        self.assertEqual([document["id"] for document in results], ["relevant"])
        self.assertIsInstance(results[0]["score"], float)
        self.assertGreater(results[0]["score"], 0)


if __name__ == "__main__":
    unittest.main()
