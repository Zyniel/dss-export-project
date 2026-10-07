"""Fakes of the DSS objects used by the plugin, and shared fixtures."""

import io
import json
import zipfile
from typing import Any, Optional

import pytest

NOTEBOOK_WITH_OUTPUTS = {
    "nbformat": 4,
    "nbformat_minor": 5,
    "metadata": {"kernelspec": {"name": "python3"}, "widgets": {"state": {"x": "customer data"}}},
    "cells": [
        {"cell_type": "markdown", "source": ["# Analysis"]},
        {
            "cell_type": "code",
            "source": ["df.head()"],
            "execution_count": 7,
            "outputs": [
                {"output_type": "execute_result", "data": {"text/plain": ["IBAN FR76..."]}}
            ],
        },
        {"cell_type": "code", "source": ["x = 1"], "execution_count": 8, "outputs": []},
    ],
}

PROJECT_VARIABLES = {
    "standard": {"schema": "SALES", "db_password": "hunter2", "nested": {"api_token": "abc"}},
    "local": {"limits": [10, 20]},
}


def build_export_archive(extra_files: Optional[dict[str, bytes]] = None) -> bytes:
    """Build an archive that looks like a DSS project export."""
    files = {
        "export-manifest.json": json.dumps({"projectKey": "SALES"}).encode("utf-8"),
        "project_config/params.json": json.dumps({"name": "Sales"}).encode("utf-8"),
        "project_config/variables.json": json.dumps(PROJECT_VARIABLES).encode("utf-8"),
        "project_config/recipes/compute_kpi.py": b"import dataiku\nprint('hello')\n",
        "project_config/ipython_notebooks/explore.ipynb": json.dumps(NOTEBOOK_WITH_OUTPUTS).encode(
            "utf-8"
        ),
    }
    if extra_files is not None:
        files.update(extra_files)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("project_config/", b"")
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


class FakeFolder:
    """A managed folder that keeps the uploaded files in memory."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.failing_prefix: Optional[str] = None

    def put_file(self, path: str, file_object: Any) -> dict[str, Any]:
        if self.failing_prefix is not None and path.startswith(self.failing_prefix):
            raise OSError("folder storage unavailable")
        content = file_object.read()
        self.files[path] = content
        return {"path": path, "size": len(content)}


class FakeProject:
    """A project of the fake instance."""

    def __init__(self, client: "FakeAdminClient", project_key: str) -> None:
        self.client = client
        self.project_key = project_key

    def export_to_file(self, path: str, options: Optional[dict[str, bool]] = None) -> None:
        self.client.export_calls.append((self.project_key, options))
        if self.project_key in self.client.failing_projects:
            raise RuntimeError("export failed on the DSS side")
        with open(path, "wb") as archive_file:
            archive_file.write(self.client.archives[self.project_key])

    def list_managed_folders(self) -> list[dict[str, Any]]:
        return list(self.client.folder_definitions)

    def get_managed_folder(self, folder_id: str) -> FakeFolder:
        self.client.requested_folder_ids.append(folder_id)
        return self.client.folder


class FakeInstanceInfo:
    def __init__(self) -> None:
        self.raw = {"nodeId": "design-01", "nodeName": "CDP Design", "nodeType": "DESIGN"}


class FakeAdminClient:
    """The privileged client of a fake instance with three projects."""

    def __init__(self) -> None:
        self.archives = {
            "AUDIT_HUB": build_export_archive(),
            "SALES": build_export_archive(),
            "RISK": build_export_archive(),
        }
        self.folder = FakeFolder()
        self.folder_definitions = [
            {"id": "aBcD1234", "name": "audit_exports"},
            {"id": "zZzZ9999", "name": "other"},
        ]
        self.failing_projects: list[str] = []
        self.export_calls: list[tuple[str, Optional[dict[str, bool]]]] = []
        self.requested_folder_ids: list[str] = []

    def list_project_keys(self) -> list[str]:
        return list(self.archives)

    def list_projects(self) -> list[dict[str, Any]]:
        return [
            {"projectKey": "SALES", "name": "Sales KPIs", "ownerLogin": "alice"},
            {"projectKey": "AUDIT_HUB", "name": "Audit hub", "ownerLogin": "admin"},
            {"projectKey": "RISK", "name": "Risk models"},
        ]

    def get_project(self, project_key: str) -> FakeProject:
        return FakeProject(self, project_key)

    def get_instance_info(self) -> FakeInstanceInfo:
        return FakeInstanceInfo()


class FakeUserClient:
    """The client of the end user who launches the macro."""

    host = "http://127.0.0.1:11200"

    def __init__(self, login: str, groups: list[str]) -> None:
        self.login = login
        self.groups = groups

    def get_auth_info(self) -> dict[str, Any]:
        return {"authIdentifier": self.login, "groups": list(self.groups)}


@pytest.fixture
def admin_client() -> FakeAdminClient:
    return FakeAdminClient()


@pytest.fixture
def auditor_client() -> FakeUserClient:
    return FakeUserClient("jane.doe@corp", ["readers", "CDP_ADMIN_AUDIT"])


@pytest.fixture
def plugin_config() -> dict[str, Any]:
    return {
        "auditor_group": "CDP_ADMIN_AUDIT",
        "hub_project_key": "AUDIT_HUB",
        "hub_folder": "audit_exports",
        "restrict_to_hub_project": True,
        "variables_redaction": "ALL",
        "max_projects_per_run": 2,
        "admin_api_key": "",
    }
