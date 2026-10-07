"""Export orchestration: everything that talks to DSS.

The flow of a run is:

1. authorize the caller with their own identity;
2. only then, obtain a privileged client;
3. for each requested project: export the metadata, sanitize the archive,
   deliver it in the hub folder and write a request record next to it.
"""

import io
import json
import logging
import os
import re
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from cdp_audit_export import __version__
from cdp_audit_export.authorization import require_auditor, require_hub_project
from cdp_audit_export.sanitizer import SanitizationReport, sanitize_archive
from cdp_audit_export.settings import PluginSettings, SettingsError, load_settings

logger = logging.getLogger(__name__)

# Every data-carrying option of the DSS project export, explicitly disabled.
# They already default to False: spelling them out protects the behaviour
# against a change of defaults in a later DSS version.
EXPORT_OPTIONS: dict[str, bool] = {
    "exportUploads": False,
    "exportManagedFS": False,
    "exportAnalysisModels": False,
    "exportSavedModels": False,
    "exportModelEvaluationStores": False,
    "exportManagedFolders": False,
    "exportAllInputDatasets": False,
    "exportAllDatasets": False,
    "exportAllInputManagedFolders": False,
    "exportGitRepository": False,
    "exportInsightsData": False,
}

PROJECT_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_]+$")
UNSAFE_FILE_CHARACTERS = re.compile(r"[^A-Za-z0-9._-]")
REQUESTS_DIRECTORY = "_requests"
ADMIN_CLIENT_PURPOSE = "cdp_audit_export"

STATUS_OK = "OK"
STATUS_FAILED = "FAILED"

ProgressCallback = Callable[[int], None]
AdminClientFactory = Callable[[Any, dict[str, Any], PluginSettings], Any]


class RequestError(Exception):
    """Raised when the request of the auditor is invalid."""


@dataclass(frozen=True)
class HubFolder:
    """The managed folder that receives the archives."""

    handle: Any
    folder_id: str
    name: str


@dataclass
class ExportResult:
    """Outcome of the export of one project."""

    project_key: str
    status: str
    archive_path: Optional[str] = None
    archive_size: int = 0
    report: Optional[SanitizationReport] = None
    error: Optional[str] = None


@dataclass
class ExportRun:
    """Outcome of a whole macro run."""

    requester: str
    hub_project_key: str
    hub_folder_id: str
    hub_folder_name: str
    results: list[ExportResult] = field(default_factory=list)


@dataclass(frozen=True)
class AuditContext:
    """What an authorized run needs: settings, caller and privileged client."""

    settings: PluginSettings
    requester: str
    admin_client: Any


def get_privileged_client(
    user_client: Any, user_auth_info: dict[str, Any], settings: PluginSettings
) -> Any:
    """Return a DSS client with administrator rights.

    Uses the admin API key of the plugin settings when one is set. Otherwise
    relies on the DSS helper, which only works in a non-impersonated macro.
    """
    if settings.admin_api_key is not None:
        import dataikuapi  # provided by the DSS runtime

        return dataikuapi.DSSClient(user_client.host, settings.admin_api_key)

    from dataiku.runnables import utils  # provided by the DSS runtime

    return utils.get_admin_dss_client(ADMIN_CLIENT_PURPOSE, user_auth_info)


def open_audit_context(
    user_client: Any,
    current_project_key: str,
    plugin_config: dict[str, Any],
    admin_client_factory: AdminClientFactory = get_privileged_client,
) -> AuditContext:
    """Authorize the caller, then build the privileged client.

    The privileged client is created last, so that a refused caller never
    triggers any administrative action.

    :param user_client: the client of the end user (``dataiku.api_client()``)
    :param current_project_key: key of the project the macro was launched from
    :param plugin_config: raw plugin settings
    :raises SettingsError: when the plugin is not configured
    :raises AccessDenied: when the caller is not allowed to run the macro
    """
    settings = load_settings(plugin_config)
    user_auth_info = user_client.get_auth_info()

    requester = require_auditor(user_auth_info, settings.auditor_group)
    require_hub_project(current_project_key, settings)

    admin_client = admin_client_factory(user_client, user_auth_info, settings)
    return AuditContext(settings=settings, requester=requester, admin_client=admin_client)


def parse_project_keys(raw_value: Any) -> list[str]:
    """Turn the macro parameter into a clean list of project keys.

    Accepts a list of strings or a single string with commas, spaces or line
    breaks between the keys. Duplicates are removed, the order is kept.
    """
    if raw_value is None:
        raw_items = []
    elif isinstance(raw_value, str):
        raw_items = [raw_value]
    else:
        raw_items = list(raw_value)

    project_keys: list[str] = []
    for raw_item in raw_items:
        for candidate in re.split(r"[,;\s]+", str(raw_item)):
            project_key = candidate.strip()
            if project_key != "" and project_key not in project_keys:
                project_keys.append(project_key)
    return project_keys


def validate_project_keys(
    requested_keys: list[str], existing_keys: list[str], max_projects: int
) -> None:
    """Check the requested project keys before anything is exported.

    :raises RequestError: when the request is empty, too large, malformed or
        targets a project that does not exist
    """
    if len(requested_keys) == 0:
        raise RequestError("No project key was given.")

    if len(requested_keys) > max_projects:
        raise RequestError(
            f"{len(requested_keys)} projects were requested, the limit is {max_projects} per run."
        )

    malformed_keys = []
    unknown_keys = []
    for project_key in requested_keys:
        if PROJECT_KEY_PATTERN.match(project_key) is None:
            malformed_keys.append(project_key)
        elif project_key not in existing_keys:
            unknown_keys.append(project_key)

    if len(malformed_keys) > 0:
        raise RequestError(f"Invalid project key(s): {', '.join(malformed_keys)}.")
    if len(unknown_keys) > 0:
        raise RequestError(
            f"Unknown project key(s): {', '.join(unknown_keys)}. "
            "Run the 'Audit: list projects' macro to find the right keys."
        )


def find_hub_folder(
    admin_client: Any, settings: PluginSettings, existing_keys: list[str]
) -> HubFolder:
    """Locate the managed folder of the hub project, by id or by name.

    :raises SettingsError: when the hub project or its folder does not exist
    """
    if settings.hub_project_key not in existing_keys:
        raise SettingsError(
            f"The hub project '{settings.hub_project_key}' does not exist on this instance."
        )

    hub_project = admin_client.get_project(settings.hub_project_key)
    folder_definitions = hub_project.list_managed_folders()

    matching_definition = None
    for folder_definition in folder_definitions:
        if folder_definition.get("id") == settings.hub_folder:
            matching_definition = folder_definition
            break
    if matching_definition is None:
        for folder_definition in folder_definitions:
            if folder_definition.get("name") == settings.hub_folder:
                matching_definition = folder_definition
                break

    if matching_definition is None:
        raise SettingsError(
            f"No managed folder named '{settings.hub_folder}' in the hub project "
            f"'{settings.hub_project_key}'."
        )

    folder_id = str(matching_definition["id"])
    return HubFolder(
        handle=hub_project.get_managed_folder(folder_id),
        folder_id=folder_id,
        name=str(matching_definition.get("name", folder_id)),
    )


def format_timestamp(moment: datetime) -> str:
    """Format a moment as a compact UTC timestamp usable in a file name."""
    return moment.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def safe_file_part(text: str) -> str:
    """Make a text safe to use inside a file name."""
    return UNSAFE_FILE_CHARACTERS.sub("_", text)


def describe_instance(admin_client: Any) -> dict[str, Any]:
    """Return what identifies the DSS node, for the manifest and the records."""
    instance_info = admin_client.get_instance_info().raw
    return {
        "nodeId": instance_info.get("nodeId"),
        "nodeName": instance_info.get("nodeName"),
        "nodeType": instance_info.get("nodeType"),
    }


def write_request_record(
    hub_folder: HubFolder,
    result: ExportResult,
    requester: str,
    moment: datetime,
    instance: dict[str, Any],
) -> str:
    """Write the record of one export request in the hub folder.

    One small JSON file is written per request, so that records are never
    rewritten. A "Files in folder" dataset can read them all.

    :returns: the path of the record in the hub folder
    """
    utc_moment = moment.astimezone(timezone.utc)
    record: dict[str, Any] = {
        "requestedAt": utc_moment.isoformat(),
        "requestedBy": requester,
        "projectKey": result.project_key,
        "status": result.status,
        "archivePath": result.archive_path,
        "archiveSize": result.archive_size,
        "error": result.error,
        "instance": instance,
        "toolVersion": __version__,
    }
    if result.report is not None:
        record["sanitization"] = result.report.to_dict()

    record_path = (
        f"/{REQUESTS_DIRECTORY}/{utc_moment:%Y}/{utc_moment:%m}/"
        f"{format_timestamp(utc_moment)}__{safe_file_part(requester)}__{result.project_key}.json"
    )
    record_bytes = json.dumps(record, indent=2, ensure_ascii=False).encode("utf-8")
    hub_folder.handle.put_file(record_path, io.BytesIO(record_bytes))
    return record_path


def export_project(
    admin_client: Any,
    hub_folder: HubFolder,
    project_key: str,
    requester: str,
    settings: PluginSettings,
    moment: datetime,
    instance: dict[str, Any],
) -> ExportResult:
    """Export, sanitize and deliver the metadata of one project.

    The raw archive only ever exists in a temporary directory, which is
    deleted before the function returns.

    :returns: the outcome, with the path of the archive in the hub folder
    """
    timestamp = format_timestamp(moment)
    archive_path = f"/{project_key}/{project_key}__{timestamp}__{safe_file_part(requester)}.zip"
    manifest = {
        "tool": "cdp-audit-export",
        "toolVersion": __version__,
        "projectKey": project_key,
        "requestedBy": requester,
        "exportedAt": moment.astimezone(timezone.utc).isoformat(),
        "instance": instance,
        "exportOptions": dict(EXPORT_OPTIONS),
    }

    with tempfile.TemporaryDirectory(prefix="cdp-audit-export-") as work_directory:
        raw_archive = os.path.join(work_directory, "raw-export.zip")
        clean_archive = os.path.join(work_directory, "sanitized-export.zip")

        project = admin_client.get_project(project_key)
        project.export_to_file(raw_archive, dict(EXPORT_OPTIONS))

        report = sanitize_archive(
            raw_archive, clean_archive, settings.variables_redaction, manifest
        )

        archive_size = os.path.getsize(clean_archive)
        with open(clean_archive, "rb") as archive_file:
            hub_folder.handle.put_file(archive_path, archive_file)

    return ExportResult(
        project_key=project_key,
        status=STATUS_OK,
        archive_path=archive_path,
        archive_size=archive_size,
        report=report,
    )


def run_export(
    user_client: Any,
    current_project_key: str,
    plugin_config: dict[str, Any],
    raw_project_keys: Any,
    progress_callback: Optional[ProgressCallback] = None,
    admin_client_factory: AdminClientFactory = get_privileged_client,
    now: Optional[datetime] = None,
) -> ExportRun:
    """Run the "export project metadata" macro.

    A project that fails does not stop the others: its failure is recorded
    and reported.

    :param user_client: the client of the end user (``dataiku.api_client()``)
    :param current_project_key: key of the project the macro was launched from
    :param plugin_config: raw plugin settings
    :param raw_project_keys: value of the "Project keys" macro parameter
    :param progress_callback: called with the number of projects processed
    :param now: moment of the request, defaults to the current time
    :raises SettingsError: when the plugin is not configured
    :raises AccessDenied: when the caller is not allowed to run the macro
    :raises RequestError: when the request is invalid
    """
    context = open_audit_context(
        user_client, current_project_key, plugin_config, admin_client_factory
    )
    settings = context.settings
    admin_client = context.admin_client
    moment = now if now is not None else datetime.now(timezone.utc)

    requested_keys = parse_project_keys(raw_project_keys)
    existing_keys = admin_client.list_project_keys()
    validate_project_keys(requested_keys, existing_keys, settings.max_projects_per_run)

    hub_folder = find_hub_folder(admin_client, settings, existing_keys)
    instance = describe_instance(admin_client)

    run = ExportRun(
        requester=context.requester,
        hub_project_key=settings.hub_project_key,
        hub_folder_id=hub_folder.folder_id,
        hub_folder_name=hub_folder.name,
    )

    for processed_count, project_key in enumerate(requested_keys, start=1):
        logger.info("Audit export of %s requested by %s", project_key, context.requester)
        try:
            result = export_project(
                admin_client,
                hub_folder,
                project_key,
                context.requester,
                settings,
                moment,
                instance,
            )
        except Exception as error:  # one failing project must not stop the run
            logger.exception("Audit export of %s failed", project_key)
            result = ExportResult(
                project_key=project_key,
                status=STATUS_FAILED,
                error=f"{type(error).__name__}: {error}",
            )

        try:
            write_request_record(hub_folder, result, context.requester, moment, instance)
        except Exception as error:  # the report must still reach the auditor
            logger.exception("Could not write the request record of %s", project_key)
            if result.status == STATUS_OK:
                result.status = STATUS_FAILED
                result.error = (
                    "The archive was delivered but its request record could not "
                    f"be written ({type(error).__name__}: {error})."
                )

        run.results.append(result)
        if progress_callback is not None:
            progress_callback(processed_count)

    return run


def list_projects(
    user_client: Any,
    current_project_key: str,
    plugin_config: dict[str, Any],
    admin_client_factory: AdminClientFactory = get_privileged_client,
) -> list[dict[str, str]]:
    """Run the "list projects" macro.

    :returns: one row per project of the instance, sorted by key, with the
        ``projectKey``, ``name`` and ``owner`` of the project
    :raises SettingsError: when the plugin is not configured
    :raises AccessDenied: when the caller is not allowed to run the macro
    """
    context = open_audit_context(
        user_client, current_project_key, plugin_config, admin_client_factory
    )

    rows = []
    for project_summary in context.admin_client.list_projects():
        rows.append(
            {
                "projectKey": str(project_summary.get("projectKey", "")),
                "name": str(project_summary.get("name", "")),
                "owner": str(project_summary.get("ownerLogin", "")),
            }
        )
    rows.sort(key=lambda row: row["projectKey"])
    return rows
