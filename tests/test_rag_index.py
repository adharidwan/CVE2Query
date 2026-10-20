import tempfile
import unittest
from pathlib import Path

from cve2checker.rag import RagIndex
from cve2checker.rag_index import index_directory, iter_documents


class RagIndexDirectoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.source = self.root / "source"
        (self.source / "queries").mkdir(parents=True)
        (self.source / ".git").mkdir()
        (self.source / "queries" / "example.ql").write_text(
            "from FunctionCall c\nselect c\n", encoding="utf-8"
        )
        (self.source / "library.qll").write_text(
            "class Source extends DataFlow::Node {}\n", encoding="utf-8"
        )
        (self.source / "README.md").write_text("CodeQL docs\n", encoding="utf-8")
        (self.source / "ignore.py").write_text("strcpy\n", encoding="utf-8")
        (self.source / ".git" / "ignored.ql").write_text(
            "select 1\n", encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_iterates_supported_extensions_and_excludes_git(self) -> None:
        documents = list(iter_documents(self.source))
        titles = {document["title"] for document in documents}
        self.assertTrue(any("example.ql" in title for title in titles))
        self.assertTrue(any("library.qll" in title for title in titles))
        self.assertTrue(any("README.md" in title for title in titles))
        self.assertFalse(any("ignore.py" in title for title in titles))
        self.assertFalse(any("ignored.ql" in title for title in titles))

    def test_chunks_long_files(self) -> None:
        long_file = self.source / "long.qll"
        long_file.write_text(
            "\n".join(f"line {number}" for number in range(1, 11)),
            encoding="utf-8",
        )
        documents = [
            document
            for document in iter_documents(self.source, chunk_lines=3)
            if "long.qll" in document["id"]
        ]
        self.assertEqual(len(documents), 4)
        self.assertEqual(documents[0]["metadata"]["start_line"], 1)
        self.assertEqual(documents[0]["metadata"]["end_line"], 3)

    def test_index_directory_and_search(self) -> None:
        index = RagIndex(self.root / "rag.sqlite")
        count = index_directory(index, "examples", self.source)
        self.assertGreaterEqual(count, 3)
        results = index.search("examples", "DataFlow")
        self.assertEqual(results[0]["id"], "library.qll#chunk-1")

    def test_invalid_source_and_limits(self) -> None:
        with self.assertRaises(ValueError):
            list(iter_documents(self.root / "missing"))
        with self.assertRaises(ValueError):
            list(iter_documents(self.source, chunk_lines=0))


if __name__ == "__main__":
    unittest.main()
