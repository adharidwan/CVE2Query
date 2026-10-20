import unittest

from cve2checker.source import (
    SourceError,
    discover_source,
    github_references,
    parse_github_url,
)

SHA = "a" * 40
OTHER_SHA = "b" * 40


def record_with_references(*urls: str) -> dict:
    return {
        "dataType": "CVE_RECORD",
        "cveMetadata": {"cveId": "CVE-2024-1234"},
        "containers": {
            "cna": {
                "references": [{"url": url} for url in urls],
            }
        },
    }


class GitHubURLTests(unittest.TestCase):
    def test_parses_commit_pull_repo_release_and_advisory(self) -> None:
        commit = parse_github_url(f"https://github.com/acme/widget/commit/{SHA}")
        self.assertEqual((commit.owner, commit.repo, commit.kind, commit.commit), ("acme", "widget", "commit", SHA))

        pull = parse_github_url("https://github.com/acme/widget/pull/42")
        self.assertEqual((pull.kind, pull.number), ("pull", 42))

        repo = parse_github_url("https://github.com/acme/widget.git")
        self.assertEqual((repo.kind, repo.repo), ("repo", "widget"))

        release = parse_github_url("https://github.com/acme/widget/releases/tag/v1.2.3")
        self.assertEqual((release.kind, release.ref), ("tag", "v1.2.3"))

        advisory = parse_github_url(
            "https://github.com/acme/widget/security/advisories/GHSA-xxxx"
        )
        self.assertEqual(advisory.kind, "advisory")

    def test_parses_api_commit_url(self) -> None:
        parsed = parse_github_url(
            f"https://api.github.com/repos/acme/widget/commits/{SHA}"
        )
        self.assertEqual(
            (parsed.owner, parsed.repo, parsed.kind, parsed.commit),
            ("acme", "widget", "commit", SHA),
        )

    def test_rejects_non_github_and_invalid_urls(self) -> None:
        self.assertIsNone(parse_github_url("https://example.com/acme/widget"))
        self.assertIsNone(parse_github_url("not a url"))
        self.assertIsNone(parse_github_url(""))


class ReferenceExtractionTests(unittest.TestCase):
    def test_extracts_and_deduplicates(self) -> None:
        record = record_with_references(
            f"https://github.com/acme/widget/commit/{SHA}",
            f"https://github.com/acme/widget/commit/{SHA}",
            "https://github.com/acme/widget/pull/7",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
        )
        references = github_references(record)
        self.assertEqual(
            [reference.kind for reference in references], ["commit", "pull"]
        )


class SourceDiscoveryTests(unittest.TestCase):
    def test_explicit_commit_is_selected(self) -> None:
        record = record_with_references(
            "https://github.com/acme/widget/pull/7",
            f"https://github.com/acme/widget/commit/{SHA}",
        )
        source = discover_source(record)
        self.assertEqual(source.owner, "acme")
        self.assertEqual(source.repo, "widget")
        self.assertEqual(source.repository_url, "https://github.com/acme/widget")
        self.assertEqual(source.fix_commit, SHA)
        self.assertEqual(source.fix_commit_source, "cve-reference")

    def test_pull_request_is_resolved_with_fetcher(self) -> None:
        calls = []

        def fetcher(url, headers):
            calls.append((url, headers))
            return {"merged": True, "merge_commit_sha": OTHER_SHA}

        record = record_with_references("https://github.com/acme/widget/pull/7")
        source = discover_source(record, fetcher=fetcher)
        self.assertEqual(source.fix_commit, OTHER_SHA)
        self.assertEqual(source.fix_commit_source, "github-pull-merge-commit")
        self.assertEqual(
            calls[0][0], "https://api.github.com/repos/acme/widget/pulls/7"
        )

    def test_preferred_commit_overrides_references(self) -> None:
        record = record_with_references(
            f"https://github.com/acme/widget/commit/{SHA}"
        )
        source = discover_source(record, preferred_commit=OTHER_SHA)
        self.assertEqual(source.fix_commit, OTHER_SHA)
        self.assertEqual(source.fix_commit_source, "user-specified")

    def test_insufficient_references_return_warnings(self) -> None:
        source = discover_source(record_with_references())
        self.assertIsNone(source.repository_url)
        self.assertIsNone(source.fix_commit)
        self.assertTrue(source.warnings)

    def test_advisory_only_does_not_guess_a_commit(self) -> None:
        record = record_with_references(
            "https://github.com/acme/widget/security/advisories/GHSA-xxxx"
        )
        source = discover_source(record)
        self.assertEqual(source.repository_url, "https://github.com/acme/widget")
        self.assertIsNone(source.fix_commit)
        self.assertTrue(any("no fix commit" in warning for warning in source.warnings))

    def test_invalid_preferred_commit_is_rejected(self) -> None:
        with self.assertRaises(SourceError):
            discover_source(record_with_references(), preferred_commit="main")


if __name__ == "__main__":
    unittest.main()
