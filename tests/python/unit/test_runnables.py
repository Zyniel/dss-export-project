"""Smoke tests of the macro entry points, with the DSS runtime stubbed."""

import importlib.util
import sys
import types
from pathlib import Path

import pytest

from cdp_audit_export.authorization import AccessDenied
from cdp_audit_export.export_service import get_privileged_client
from cdp_audit_export.settings import load_settings

PLUGIN_ROOT = Path(__file__).resolve().parents[3]


class StubResultTable:
    def __init__(self):
        self.columns = []
        self.records = []

    def add_column(self, column_id, label, column_type):
        self.columns.append((column_id, label, column_type))

    def add_record(self, record):
        self.records.append(record)


@pytest.fixture
def dss_runtime(monkeypatch, admin_client, auditor_client):
    """Install stub ``dataiku`` modules and return what they recorded."""
    recorded = {"admin_client_requests": [], "user_client": auditor_client}

    def get_admin_dss_client(purpose, user_auth_info):
        recorded["admin_client_requests"].append((purpose, user_auth_info["authIdentifier"]))
        return admin_client

    dataiku_module = types.ModuleType("dataiku")
    dataiku_module.api_client = lambda: recorded["user_client"]
    runnables_module = types.ModuleType("dataiku.runnables")
    runnables_module.Runnable = object
    runnables_module.ResultTable = StubResultTable
    utils_module = types.ModuleType("dataiku.runnables.utils")
    utils_module.get_admin_dss_client = get_admin_dss_client
    runnables_module.utils = utils_module
    dataiku_module.runnables = runnables_module

    monkeypatch.setitem(sys.modules, "dataiku", dataiku_module)
    monkeypatch.setitem(sys.modules, "dataiku.runnables", runnables_module)
    monkeypatch.setitem(sys.modules, "dataiku.runnables.utils", utils_module)
    return recorded


def load_runnable(macro_id):
    path = PLUGIN_ROOT / "python-runnables" / macro_id / "runnable.py"
    spec = importlib.util.spec_from_file_location(f"runnable_{macro_id.replace('-', '_')}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_export_macro_end_to_end(dss_runtime, admin_client, plugin_config):
    module = load_runnable("audit-export-project")
    macro = module.AuditExportProjectRunnable(
        "AUDIT_HUB", {"project_keys": ["SALES", "RISK"]}, plugin_config
    )
    progress = []

    assert macro.get_progress_target() == (2, "NONE")
    page = macro.run(progress.append)

    assert "2 of 2 project(s) exported" in page
    assert progress == [1, 2]
    assert dss_runtime["admin_client_requests"] == [("cdp_audit_export", "jane.doe@corp")]
    delivered_archives = [path for path in admin_client.folder.files if path.endswith(".zip")]
    assert len(delivered_archives) == 2


def test_export_macro_refuses_a_non_auditor(dss_runtime, admin_client, plugin_config):
    dss_runtime["user_client"].groups = ["readers"]
    module = load_runnable("audit-export-project")
    macro = module.AuditExportProjectRunnable(
        "AUDIT_HUB", {"project_keys": ["SALES"]}, plugin_config
    )

    with pytest.raises(AccessDenied):
        macro.run(lambda count: None)

    assert dss_runtime["admin_client_requests"] == []
    assert admin_client.folder.files == {}


def test_list_macro_returns_a_table(dss_runtime, plugin_config):
    module = load_runnable("audit-list-projects")
    macro = module.AuditListProjectsRunnable("AUDIT_HUB", {}, plugin_config)

    assert macro.get_progress_target() is None
    table = macro.run(lambda count: None)

    assert [column[0] for column in table.columns] == ["project_key", "name", "owner"]
    assert table.records[0] == ["AUDIT_HUB", "Audit hub", "admin"]
    assert len(table.records) == 3


def test_admin_api_key_setting_takes_over_the_helper(dss_runtime, auditor_client, plugin_config):
    pytest.importorskip("dataikuapi")
    plugin_config["admin_api_key"] = "admin-key"
    settings = load_settings(plugin_config)

    client = get_privileged_client(auditor_client, auditor_client.get_auth_info(), settings)

    assert client.host == "http://127.0.0.1:11200"
    assert client.api_key == "admin-key"
    assert dss_runtime["admin_client_requests"] == []
