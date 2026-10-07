import io
import json
import zipfile
from datetime import datetime, timezone

import pytest
from conftest import FakeUserClient

from cdp_audit_export.authorization import AccessDenied
from cdp_audit_export.export_service import (
    EXPORT_OPTIONS,
    RequestError,
    list_projects,
    parse_project_keys,
    run_export,
    validate_project_keys,
)
from cdp_audit_export.settings import SettingsError

REQUEST_TIME = datetime(2026, 10, 7, 9, 5, 30, tzinfo=timezone.utc)
SALES_ARCHIVE = "/SALES/SALES__20261007T090530Z__jane.doe_corp.zip"
SALES_RECORD = "/_requests/2026/10/20261007T090530Z__jane.doe_corp__SALES.json"


class FactorySpy:
    """Admin client factory that records whether it was called."""

    def __init__(self, admin_client):
        self.admin_client = admin_client
        self.calls = []

    def __call__(self, user_client, user_auth_info, settings):
        self.calls.append(user_auth_info["authIdentifier"])
        return self.admin_client


def export(user_client, plugin_config, factory, project_keys, current_project="AUDIT_HUB"):
    return run_export(
        user_client=user_client,
        current_project_key=current_project,
        plugin_config=plugin_config,
        raw_project_keys=project_keys,
        admin_client_factory=factory,
        now=REQUEST_TIME,
    )


def test_export_delivers_a_sanitized_archive(admin_client, auditor_client, plugin_config):
    factory = FactorySpy(admin_client)

    run = export(auditor_client, plugin_config, factory, ["SALES"])

    assert run.requester == "jane.doe@corp"
    assert run.hub_folder_id == "aBcD1234"
    assert admin_client.requested_folder_ids == ["aBcD1234"]
    assert [(result.project_key, result.status) for result in run.results] == [("SALES", "OK")]
    assert run.results[0].archive_path == SALES_ARCHIVE
    assert run.results[0].archive_size == len(admin_client.folder.files[SALES_ARCHIVE])

    with zipfile.ZipFile(io.BytesIO(admin_client.folder.files[SALES_ARCHIVE])) as archive:
        manifest = json.loads(archive.read("audit-manifest.json"))
        notebook = archive.read("project_config/ipython_notebooks/explore.ipynb")
    assert manifest["requestedBy"] == "jane.doe@corp"
    assert manifest["exportedAt"] == "2026-10-07T09:05:30+00:00"
    assert manifest["instance"]["nodeId"] == "design-01"
    assert manifest["exportOptions"] == EXPORT_OPTIONS
    assert b"IBAN" not in notebook


def test_every_data_option_is_disabled(admin_client, auditor_client, plugin_config):
    export(auditor_client, plugin_config, FactorySpy(admin_client), ["SALES"])

    project_key, options = admin_client.export_calls[0]
    assert project_key == "SALES"
    assert options == EXPORT_OPTIONS
    assert len(options) == 11
    assert not any(options.values())


def test_request_record_is_written(admin_client, auditor_client, plugin_config):
    export(auditor_client, plugin_config, FactorySpy(admin_client), ["SALES"])

    record = json.loads(admin_client.folder.files[SALES_RECORD])
    assert record["requestedBy"] == "jane.doe@corp"
    assert record["projectKey"] == "SALES"
    assert record["status"] == "OK"
    assert record["archivePath"] == SALES_ARCHIVE
    assert record["sanitization"]["notebooksCleaned"] == 1


def test_non_auditor_is_refused_before_any_privileged_action(admin_client, plugin_config):
    factory = FactorySpy(admin_client)
    outsider = FakeUserClient("bob", ["readers"])

    with pytest.raises(AccessDenied):
        export(outsider, plugin_config, factory, ["SALES"])

    assert factory.calls == []
    assert admin_client.export_calls == []
    assert admin_client.folder.files == {}


def test_run_outside_the_hub_project_is_refused(admin_client, auditor_client, plugin_config):
    factory = FactorySpy(admin_client)

    with pytest.raises(AccessDenied, match="AUDIT_HUB"):
        export(auditor_client, plugin_config, factory, ["SALES"], current_project="SALES")

    assert factory.calls == []


def test_a_failing_project_does_not_stop_the_others(admin_client, auditor_client, plugin_config):
    admin_client.failing_projects.append("SALES")
    progress = []

    run = run_export(
        user_client=auditor_client,
        current_project_key="AUDIT_HUB",
        plugin_config=plugin_config,
        raw_project_keys=["SALES", "RISK"],
        progress_callback=progress.append,
        admin_client_factory=FactorySpy(admin_client),
        now=REQUEST_TIME,
    )

    assert [(result.project_key, result.status) for result in run.results] == [
        ("SALES", "FAILED"),
        ("RISK", "OK"),
    ]
    assert run.results[0].error == "RuntimeError: export failed on the DSS side"
    assert progress == [1, 2]
    assert SALES_ARCHIVE not in admin_client.folder.files
    assert json.loads(admin_client.folder.files[SALES_RECORD])["status"] == "FAILED"


def test_missing_request_record_fails_the_export(admin_client, auditor_client, plugin_config):
    admin_client.folder.failing_prefix = "/_requests/"

    run = export(auditor_client, plugin_config, FactorySpy(admin_client), ["SALES"])

    assert run.results[0].status == "FAILED"
    assert "request record could not be written" in run.results[0].error


@pytest.mark.parametrize(
    ("project_keys", "message"),
    [
        ([], "No project key"),
        (["SALES", "RISK", "AUDIT_HUB"], "limit is 2"),
        (["../etc"], "Invalid project key"),
        (["NOPE"], "Unknown project key"),
    ],
)
def test_invalid_requests_export_nothing(
    admin_client, auditor_client, plugin_config, project_keys, message
):
    with pytest.raises(RequestError, match=message):
        export(auditor_client, plugin_config, FactorySpy(admin_client), project_keys)

    assert admin_client.export_calls == []
    assert admin_client.folder.files == {}


def test_hub_folder_can_be_given_by_id(admin_client, auditor_client, plugin_config):
    plugin_config["hub_folder"] = "zZzZ9999"

    run = export(auditor_client, plugin_config, FactorySpy(admin_client), ["SALES"])

    assert (run.hub_folder_id, run.hub_folder_name) == ("zZzZ9999", "other")


@pytest.mark.parametrize(
    ("setting", "value", "message"),
    [("hub_folder", "missing", "No managed folder"), ("hub_project_key", "GONE", "does not exist")],
)
def test_misconfigured_hub_is_reported(
    admin_client, auditor_client, plugin_config, setting, value, message
):
    plugin_config[setting] = value
    plugin_config["restrict_to_hub_project"] = False

    with pytest.raises(SettingsError, match=message):
        export(auditor_client, plugin_config, FactorySpy(admin_client), ["SALES"])

    assert admin_client.export_calls == []


@pytest.mark.parametrize(
    ("raw_value", "expected"),
    [
        (["SALES", "RISK"], ["SALES", "RISK"]),
        ("SALES, RISK;AUDIT_HUB\nSALES", ["SALES", "RISK", "AUDIT_HUB"]),
        ([" SALES ", "", "SALES"], ["SALES"]),
        (None, []),
    ],
)
def test_project_keys_parsing(raw_value, expected):
    assert parse_project_keys(raw_value) == expected


def test_validation_accepts_a_correct_request():
    validate_project_keys(["SALES"], ["SALES", "RISK"], 5)


def test_list_projects_is_sorted_and_reserved_to_auditors(
    admin_client, auditor_client, plugin_config
):
    rows = list_projects(auditor_client, "AUDIT_HUB", plugin_config, FactorySpy(admin_client))

    assert rows == [
        {"projectKey": "AUDIT_HUB", "name": "Audit hub", "owner": "admin"},
        {"projectKey": "RISK", "name": "Risk models", "owner": ""},
        {"projectKey": "SALES", "name": "Sales KPIs", "owner": "alice"},
    ]

    factory = FactorySpy(admin_client)
    with pytest.raises(AccessDenied):
        list_projects(FakeUserClient("bob", []), "AUDIT_HUB", plugin_config, factory)
    assert factory.calls == []
