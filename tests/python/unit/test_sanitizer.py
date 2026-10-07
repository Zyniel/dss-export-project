import io
import json
import zipfile

import pytest
from conftest import NOTEBOOK_WITH_OUTPUTS, build_export_archive

from cdp_audit_export.sanitizer import (
    MANIFEST_FILE_NAME,
    REDACTED_VALUE,
    is_secret_name,
    redact_all_values,
    redact_secret_values,
    sanitize_archive,
    strip_notebook_outputs,
)


def run_sanitizer(tmp_path, archive_bytes, redaction_mode="ALL"):
    source_path = tmp_path / "raw.zip"
    target_path = tmp_path / "clean.zip"
    source_path.write_bytes(archive_bytes)
    report = sanitize_archive(
        str(source_path), str(target_path), redaction_mode, {"projectKey": "SALES"}
    )
    with zipfile.ZipFile(target_path) as archive:
        contents = {name: archive.read(name) for name in archive.namelist()}
    return report, contents


def test_notebook_outputs_are_removed(tmp_path):
    report, contents = run_sanitizer(tmp_path, build_export_archive())

    notebook_bytes = contents["project_config/ipython_notebooks/explore.ipynb"]
    notebook = json.loads(notebook_bytes)
    code_cells = [cell for cell in notebook["cells"] if cell["cell_type"] == "code"]

    assert [cell["outputs"] for cell in code_cells] == [[], []]
    assert [cell["execution_count"] for cell in code_cells] == [None, None]
    assert code_cells[0]["source"] == ["df.head()"]
    assert notebook["cells"][0] == {"cell_type": "markdown", "source": ["# Analysis"]}
    assert "widgets" not in notebook["metadata"]
    assert b"IBAN" not in notebook_bytes
    assert b"customer data" not in notebook_bytes
    assert report.notebooks_cleaned == 1
    assert report.notebook_cells_cleared == 1


def test_legacy_notebook_format_is_handled():
    notebook = {
        "nbformat": 3,
        "worksheets": [
            {"cells": [{"cell_type": "code", "prompt_number": 4, "outputs": [{"text": "data"}]}]}
        ],
    }

    assert strip_notebook_outputs(notebook) == 1
    assert notebook["worksheets"][0]["cells"][0] == {"cell_type": "code", "outputs": []}


def test_all_variable_values_are_redacted_by_default(tmp_path):
    report, contents = run_sanitizer(tmp_path, build_export_archive())

    variables = json.loads(contents["project_config/variables.json"])

    assert variables == {
        "standard": {
            "schema": REDACTED_VALUE,
            "db_password": REDACTED_VALUE,
            "nested": {"api_token": REDACTED_VALUE},
        },
        "local": {"limits": [REDACTED_VALUE, REDACTED_VALUE]},
    }
    assert report.variables_files_redacted == 1
    assert report.variable_values_redacted == 5


def test_secret_keys_mode_only_redacts_secret_looking_names(tmp_path):
    report, contents = run_sanitizer(tmp_path, build_export_archive(), "SECRET_KEYS")

    variables = json.loads(contents["project_config/variables.json"])

    assert variables == {
        "standard": {
            "schema": "SALES",
            "db_password": REDACTED_VALUE,
            "nested": {"api_token": REDACTED_VALUE},
        },
        "local": {"limits": [10, 20]},
    }
    assert report.variable_values_redacted == 2


def test_none_mode_keeps_variables_untouched(tmp_path):
    archive_bytes = build_export_archive()
    report, contents = run_sanitizer(tmp_path, archive_bytes, "NONE")

    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as original:
        assert contents["project_config/variables.json"] == original.read(
            "project_config/variables.json"
        )
    assert report.variables_files_redacted == 0


def test_local_variables_file_is_redacted_too(tmp_path):
    extra_files = {"project_config/localvariables.json": b'{"vault_secret": "xyz"}'}
    _, contents = run_sanitizer(tmp_path, build_export_archive(extra_files))

    assert json.loads(contents["project_config/localvariables.json"]) == {
        "vault_secret": REDACTED_VALUE
    }


def test_other_files_are_copied_byte_for_byte(tmp_path):
    archive_bytes = build_export_archive()
    _, contents = run_sanitizer(tmp_path, archive_bytes)

    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as original:
        for name in (
            "export-manifest.json",
            "project_config/params.json",
            "project_config/recipes/compute_kpi.py",
        ):
            assert contents[name] == original.read(name)
    assert "project_config/" in contents


def test_unreadable_files_are_dropped_not_delivered(tmp_path):
    extra_files = {
        "project_config/ipython_notebooks/broken.ipynb": b"{not json with IBAN FR76",
        "project_config/ipython_notebooks/list.ipynb": b"[1, 2]",
        "project_config/lib/variables.json": b"\xff\xfe secret",
    }
    report, contents = run_sanitizer(tmp_path, build_export_archive(extra_files))

    for name in extra_files:
        assert name not in contents
    assert sorted(report.files_dropped) == sorted(extra_files)
    assert report.notebooks_cleaned == 1


def test_manifest_describes_the_export(tmp_path):
    report, contents = run_sanitizer(tmp_path, build_export_archive())

    manifest = json.loads(contents[MANIFEST_FILE_NAME])

    assert manifest["projectKey"] == "SALES"
    assert manifest["variablesRedaction"] == "ALL"
    assert manifest["sanitization"] == report.to_dict()
    assert manifest["sanitization"]["filesKept"] == 5


def test_exported_file_cannot_replace_the_manifest(tmp_path):
    extra_files = {MANIFEST_FILE_NAME: b'{"requestedBy": "someone else"}'}
    report, contents = run_sanitizer(tmp_path, build_export_archive(extra_files))

    assert json.loads(contents[MANIFEST_FILE_NAME])["projectKey"] == "SALES"
    assert MANIFEST_FILE_NAME in report.files_dropped


def test_source_notebook_fixture_is_not_modified(tmp_path):
    run_sanitizer(tmp_path, build_export_archive())
    assert NOTEBOOK_WITH_OUTPUTS["cells"][1]["outputs"] != []


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("DB_PASSWORD", True),
        ("apiKey", True),
        ("vault_token", True),
        ("client-secret", True),
        ("schema", False),
        ("primary_key_column", False),
    ],
)
def test_secret_name_detection(name, expected):
    assert is_secret_name(name) is expected


def test_redaction_helpers_count_values():
    tree = {"a": 1, "b": [True, None], "password": {"x": 1}}

    assert redact_all_values(tree)[1] == 4
    assert redact_secret_values(tree) == (
        {"a": 1, "b": [True, None], "password": REDACTED_VALUE},
        1,
    )
