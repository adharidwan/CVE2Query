import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from cve2checker.sarif import (
    SarifError,
    SarifLocation,
    location_intersects,
    parse_sarif,
    result_locations,
)


def _physical(
    uri: str,
    start_line: int,
    end_line: int | None = None,
    base_id: str | None = None,
) -> dict:
    artifact_location = {"uri": uri}
    if base_id is not None:
        artifact_location["uriBaseId"] = base_id
    region = {"startLine": start_line}
    if end_line is not None:
        region["endLine"] = end_line
    return {
        "physicalLocation": {
            "artifactLocation": artifact_location,
            "region": region,
        }
    }


class SarifParsingTests(unittest.TestCase):
    def test_parses_results_locations_code_flows_and_multiple_runs(self) -> None:
        document = {
            "version": "2.1.0",
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "cpp/overflow",
                            "message": {"text": "buffer overflow"},
                            "level": "error",
                            "locations": [
                                {
                                    **_physical("src/a.c", 10, 12),
                                    "logicalLocations": [{"name": "copy"}],
                                },
                                {"logicalLocations": [{"name": "no physical"}]},
                            ],
                            "codeFlows": [
                                {
                                    "threadFlows": [
                                        {
                                            "locations": [
                                                {
                                                    "location": _physical(
                                                        "src/a.c", 1, 1
                                                    )
                                                },
                                                {
                                                    "location": {
                                                        "logicalLocations": [
                                                            {"name": "step"}
                                                        ]
                                                    }
                                                },
                                                {
                                                    "location": _physical(
                                                        "src/b.c", 5
                                                    )
                                                },
                                            ]
                                        }
                                    ]
                                }
                            ],
                        },
                        {"message": {"markdown": "**second**"}},
                        {"ruleId": "no-locations"},
                    ]
                },
                {
                    "results": [
                        {
                            "ruleId": "other/rule",
                            "message": "plain message",
                            "level": "note",
                            "locations": [_physical("lib/c.c", 3, 4)],
                        }
                    ]
                },
            ],
        }

        results = parse_sarif(json.dumps(document))

        self.assertEqual(len(results), 4)
        first = results[0]
        self.assertEqual(first.rule_id, "cpp/overflow")
        self.assertEqual(first.message, "buffer overflow")
        self.assertEqual(first.level, "error")
        self.assertEqual([location.file for location in first.locations], ["src/a.c"])
        self.assertEqual(
            [(location.file, location.start_line, location.end_line) for location in first.code_flow_locations],
            [("src/a.c", 1, 1), ("src/b.c", 5, 5)],
        )
        self.assertEqual(len(result_locations(first)), 3)

        second = results[1]
        self.assertEqual(second.rule_id, "")
        self.assertEqual(second.message, "**second**")
        self.assertEqual(second.level, "warning")
        self.assertEqual(second.locations, [])
        self.assertEqual(second.code_flow_locations, [])

        third = results[2]
        self.assertEqual(third.rule_id, "no-locations")
        self.assertEqual(third.message, "")
        self.assertEqual(third.locations, [])

        fourth = results[3]
        self.assertEqual(fourth.rule_id, "other/rule")
        self.assertEqual(fourth.message, "plain message")
        self.assertEqual(fourth.level, "note")
        self.assertEqual([location.file for location in fourth.locations], ["lib/c.c"])

    def test_malformed_results_do_not_raise(self) -> None:
        document = {
            "runs": [
                None,
                {
                    "results": [
                        None,
                        7,
                        {},
                        {
                            "locations": [
                                None,
                                {},
                                {"physicalLocation": []},
                                {"physicalLocation": {}},
                            ],
                            "codeFlows": [
                                {"threadFlows": [{"locations": [None, {}]}]},
                                "not a code flow",
                            ],
                        },
                    ]
                },
            ]
        }

        results = parse_sarif(json.dumps(document))

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].locations, [])
        self.assertEqual(len(results[1].locations), 1)
        self.assertEqual(results[1].locations[0].file, "")
        self.assertEqual(results[1].locations[0].start_line, 0)
        self.assertEqual(results[1].code_flow_locations, [])

    def test_resolves_file_and_relative_uris(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            file_uri = (root / "src" / "with space.c").as_uri()
            document = {
                "version": "2.1.0",
                "runs": [
                    {
                        "originalUriBaseIds": {"SRCROOT": {"uri": root.as_uri() + "/"}},
                        "results": [
                            {
                                "ruleId": "test/rule",
                                "message": {"text": "message"},
                                "locations": [
                                    _physical(
                                        "src\\nested%20dir\\app.c",
                                        1,
                                        2,
                                        "SRCROOT",
                                    ),
                                    _physical(file_uri, 3, 4, "SRCROOT"),
                                    _physical("./src/../src/plain.c", 5),
                                ],
                            }
                        ],
                    }
                ],
            }

            result = parse_sarif(json.dumps(document))[0]

        self.assertEqual(
            [location.file for location in result.locations],
            ["src/nested dir/app.c", "src/with space.c", "src/plain.c"],
        )
        self.assertEqual(result.locations[0].uri, "src\\nested%20dir\\app.c")
        self.assertEqual(result.locations[1].uri, file_uri)
        self.assertEqual(result.locations[1].start_line, 3)
        self.assertEqual(result.locations[1].end_line, 4)

    def test_resolves_file_uri_without_base_to_absolute_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "src" / "main.c"
            document = {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "test/rule",
                                "message": {"text": "message"},
                                "locations": [_physical(path.as_uri(), 8)],
                            }
                        ]
                    }
                ]
            }

            location = parse_sarif(json.dumps(document))[0].locations[0]

        self.assertEqual(location.file, path.as_posix())
        self.assertEqual(location.uri, path.as_uri())
        self.assertEqual(location.end_line, 8)

    @unittest.skipUnless(os.name == "nt", "Windows drive paths are Windows-specific")
    def test_resolves_windows_drive_file_uri_and_percent_encoding(self) -> None:
        uri = "file:///C:/Users/Test%20User/src/app.c"
        document = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "test/rule",
                            "message": {"text": "message"},
                            "locations": [_physical(uri, 1, 2)],
                        }
                    ]
                }
            ]
        }

        location = parse_sarif(json.dumps(document))[0].locations[0]

        self.assertEqual(location.file, "C:/Users/Test User/src/app.c")
        self.assertEqual(location.uri, uri)

    def test_parse_accepts_path_and_json_text(self) -> None:
        document = {
            "version": "2.1.0",
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "test/rule",
                            "message": {"text": "message"},
                            "locations": [_physical("src/app.c", 1, 2)],
                        }
                    ]
                }
            ],
        }
        expected = parse_sarif(json.dumps(document))

        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "results.sarif"
            path.write_text(json.dumps(document), encoding="utf-8")

            from_string_path = parse_sarif(str(path))
            from_path_object = parse_sarif(path)

        self.assertEqual(from_string_path, expected)
        self.assertEqual(from_path_object, expected)

    def test_invalid_sarif_raises(self) -> None:
        invalid_documents = (
            "not json at all",
            "{",
            json.dumps([]),
            json.dumps({"version": "2.1.0"}),
            json.dumps({"version": "2.1.0", "runs": {}}),
            json.dumps({"version": "2.0.0", "runs": []}),
        )
        for document in invalid_documents:
            with self.subTest(document=document), self.assertRaises(SarifError):
                parse_sarif(document)

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            broken = root / "broken.sarif"
            broken.write_text("{not json", encoding="utf-8")
            with self.assertRaises(SarifError):
                parse_sarif(broken)
            with self.assertRaises(SarifError):
                parse_sarif(root / "missing.sarif")


class SarifIntersectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.location = SarifLocation(
            file="src/app.c",
            start_line=10,
            end_line=20,
            uri="src/app.c",
        )

    def test_intersects_overlapping_and_inclusive_ranges(self) -> None:
        changed = [
            {"file": "src/app.c", "start": 12, "end": 15},
            {"file": "src/app.c", "start": 20, "end": 25},
            {"file": "src/app.c", "start": 5, "end": 10},
            {"file": "src/app.c", "start": 1, "end": 9},
            {"file": "src/app.c", "start": 21, "end": 30},
        ]

        self.assertTrue(location_intersects(self.location, [changed[0]]))
        self.assertTrue(location_intersects(self.location, [changed[1]]))
        self.assertTrue(location_intersects(self.location, [changed[2]]))
        self.assertFalse(location_intersects(self.location, [changed[3]]))
        self.assertFalse(location_intersects(self.location, [changed[4]]))
        self.assertTrue(
            location_intersects(
                self.location,
                [{"file": "src/other.c", "start": 1, "end": 100}, changed[0]],
            )
        )

    def test_rejects_unknown_files_and_invalid_ranges(self) -> None:
        self.assertFalse(
            location_intersects(
                self.location, [{"file": "src/unknown.c", "start": 10, "end": 20}]
            )
        )
        self.assertFalse(
            location_intersects(
                self.location, [{"path": "src/app.c", "start": 10, "end": 20}]
            )
        )
        self.assertFalse(
            location_intersects(
                self.location, [{"file": "src/app.c", "start": 0, "end": 20}]
            )
        )
        self.assertFalse(
            location_intersects(
                self.location, [{"file": "src/app.c", "start": 10, "end": 0}]
            )
        )
        self.assertFalse(
            location_intersects(
                self.location, [{"file": "src/app.c", "start": 20, "end": 10}]
            )
        )
        self.assertFalse(
            location_intersects(
                self.location, [{"file": "src/app.c", "start": None, "end": 20}]
            )
        )
        self.assertFalse(location_intersects(self.location, [None, object()]))
        self.assertFalse(
            location_intersects(
                SarifLocation("src/app.c", 0, 0, "src/app.c"),
                [{"file": "src/app.c", "start": 1, "end": 1}],
            )
        )
        self.assertFalse(
            location_intersects(
                SarifLocation("src/app.c", 20, 10, "src/app.c"),
                [{"file": "src/app.c", "start": 1, "end": 100}],
            )
        )

    def test_accepts_mapping_items_and_path_objects(self) -> None:
        changed = {
            "file": Path("src") / "app.c",
            "start": 15,
            "end": 16,
        }

        self.assertTrue(location_intersects(self.location, changed))
        self.assertTrue(location_intersects(self.location, [changed]))

    def test_accepts_objects_with_file_start_and_end(self) -> None:
        changed = SimpleNamespace(file="src/app.c", start=15, end=16)
        outside = SimpleNamespace(file="src/app.c", start=21, end=22)
        other = SimpleNamespace(file="src/other.c", start=15, end=16)

        self.assertTrue(location_intersects(self.location, [changed]))
        self.assertFalse(location_intersects(self.location, [outside]))
        self.assertFalse(location_intersects(self.location, [other]))

    @unittest.skipUnless(os.name == "nt", "Windows paths are case-insensitive")
    def test_windows_paths_are_case_insensitive(self) -> None:
        changed = SimpleNamespace(file="SRC\\APP.C", start=15, end=16)

        self.assertTrue(location_intersects(self.location, [changed]))
        self.assertTrue(
            location_intersects(
                self.location,
                [{"file": "SRC/APP.C", "start": 15, "end": 16}],
            )
        )


if __name__ == "__main__":
    unittest.main()
