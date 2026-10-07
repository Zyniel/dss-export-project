"""Sanitization of a project export archive.

A "no data" export still carries content that auditors and analysis tools
should not receive:

* Jupyter notebooks keep the outputs of their cells (tables, charts, prints);
* project variables may hold secrets.

This module rewrites the archive without those elements. It never extracts
files to disk and never fails open: a file that should be cleaned but cannot
be parsed is dropped from the delivered archive and reported.
"""

import json
import zipfile
from dataclasses import dataclass, field
from typing import Any

from cdp_audit_export.settings import REDACT_ALL, REDACT_NONE, REDACT_SECRET_KEYS

MANIFEST_FILE_NAME = "audit-manifest.json"
REDACTED_VALUE = "***REDACTED***"

NOTEBOOK_SUFFIX = ".ipynb"
VARIABLES_FILE_NAMES = ("variables.json", "localvariables.json")

# A variable is treated as a secret when its name contains one of these words.
SECRET_NAME_HINTS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "credential",
    "privatekey",
    "private_key",
    "accesskey",
    "access_key",
)


@dataclass
class SanitizationReport:
    """What the sanitization changed in an archive."""

    files_kept: int = 0
    notebooks_cleaned: int = 0
    notebook_cells_cleared: int = 0
    variables_files_redacted: int = 0
    variable_values_redacted: int = 0
    files_dropped: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return the report as a JSON-serializable dict."""
        return {
            "filesKept": self.files_kept,
            "notebooksCleaned": self.notebooks_cleaned,
            "notebookCellsCleared": self.notebook_cells_cleared,
            "variablesFilesRedacted": self.variables_files_redacted,
            "variableValuesRedacted": self.variable_values_redacted,
            "filesDropped": list(self.files_dropped),
        }


class UnreadableContent(Exception):
    """Raised when a file that must be cleaned cannot be parsed."""


def strip_notebook_outputs(notebook: dict[str, Any]) -> int:
    """Remove the cell outputs of a Jupyter notebook, in place.

    Handles the current notebook format (cells at the top level) and the
    legacy one (cells inside worksheets).

    :returns: the number of code cells that had outputs
    """
    cell_lists = []

    top_level_cells = notebook.get("cells")
    if isinstance(top_level_cells, list):
        cell_lists.append(top_level_cells)

    worksheets = notebook.get("worksheets")
    if isinstance(worksheets, list):
        for worksheet in worksheets:
            if isinstance(worksheet, dict) and isinstance(worksheet.get("cells"), list):
                cell_lists.append(worksheet["cells"])

    cells_cleared = 0
    for cells in cell_lists:
        for cell in cells:
            if not isinstance(cell, dict) or cell.get("cell_type") != "code":
                continue
            if cell.get("outputs"):
                cells_cleared += 1
            cell["outputs"] = []
            if "execution_count" in cell:
                cell["execution_count"] = None
            if "prompt_number" in cell:
                del cell["prompt_number"]

    # Interactive widgets store a copy of the displayed data in the metadata.
    metadata = notebook.get("metadata")
    if isinstance(metadata, dict) and "widgets" in metadata:
        del metadata["widgets"]

    return cells_cleared


def is_secret_name(name: str) -> bool:
    """Tell whether a variable name looks like it holds a secret."""
    lowered_name = name.lower()
    for hint in SECRET_NAME_HINTS:
        if hint in lowered_name:
            return True
    return False


def redact_all_values(node: Any) -> tuple[Any, int]:
    """Replace every value of a JSON tree, keeping the names and the structure.

    :returns: the redacted tree and the number of values replaced
    """
    if isinstance(node, dict):
        redacted_dict = {}
        redacted_count = 0
        for name, value in node.items():
            redacted_value, value_count = redact_all_values(value)
            redacted_dict[name] = redacted_value
            redacted_count += value_count
        return redacted_dict, redacted_count

    if isinstance(node, list):
        redacted_list = []
        redacted_count = 0
        for item in node:
            redacted_item, item_count = redact_all_values(item)
            redacted_list.append(redacted_item)
            redacted_count += item_count
        return redacted_list, redacted_count

    return REDACTED_VALUE, 1


def redact_secret_values(node: Any) -> tuple[Any, int]:
    """Replace the values stored under secret-looking names in a JSON tree.

    :returns: the redacted tree and the number of values replaced
    """
    if isinstance(node, dict):
        redacted_dict = {}
        redacted_count = 0
        for name, value in node.items():
            if is_secret_name(str(name)):
                redacted_dict[name] = REDACTED_VALUE
                redacted_count += 1
                continue
            redacted_value, value_count = redact_secret_values(value)
            redacted_dict[name] = redacted_value
            redacted_count += value_count
        return redacted_dict, redacted_count

    if isinstance(node, list):
        redacted_list = []
        redacted_count = 0
        for item in node:
            redacted_item, item_count = redact_secret_values(item)
            redacted_list.append(redacted_item)
            redacted_count += item_count
        return redacted_list, redacted_count

    return node, 0


def _parse_json(content: bytes) -> Any:
    """Parse UTF-8 JSON content.

    :raises UnreadableContent: when the content is not valid UTF-8 JSON
    """
    try:
        return json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise UnreadableContent(str(error)) from error


def _to_json_bytes(document: Any) -> bytes:
    """Serialize a JSON document the way DSS configuration files are written."""
    return json.dumps(document, indent=2, ensure_ascii=False).encode("utf-8")


def clean_notebook(content: bytes) -> tuple[bytes, int]:
    """Return a notebook without its outputs, and the number of cells cleared.

    :raises UnreadableContent: when the notebook cannot be parsed
    """
    notebook = _parse_json(content)
    if not isinstance(notebook, dict):
        raise UnreadableContent("the notebook is not a JSON object")
    cells_cleared = strip_notebook_outputs(notebook)
    return _to_json_bytes(notebook), cells_cleared


def redact_variables(content: bytes, redaction_mode: str) -> tuple[bytes, int]:
    """Return a variables file with its values redacted, and the number of values replaced.

    :param redaction_mode: ``ALL`` or ``SECRET_KEYS``
    :raises UnreadableContent: when the file cannot be parsed
    """
    variables = _parse_json(content)
    if redaction_mode == REDACT_ALL:
        redacted_variables, redacted_count = redact_all_values(variables)
    elif redaction_mode == REDACT_SECRET_KEYS:
        redacted_variables, redacted_count = redact_secret_values(variables)
    else:
        raise ValueError(f"Unsupported redaction mode: {redaction_mode}")
    return _to_json_bytes(redacted_variables), redacted_count


def _file_name(archive_path: str) -> str:
    """Return the last segment of a path inside the archive, in lower case."""
    return archive_path.rsplit("/", 1)[-1].lower()


def _write_entry(target: zipfile.ZipFile, source_info: zipfile.ZipInfo, content: bytes) -> None:
    """Write one entry in the target archive, keeping its name and date."""
    target_info = zipfile.ZipInfo(filename=source_info.filename, date_time=source_info.date_time)
    target_info.compress_type = zipfile.ZIP_DEFLATED
    target_info.external_attr = source_info.external_attr
    target.writestr(target_info, content)


def sanitize_archive(
    source_path: str,
    target_path: str,
    redaction_mode: str,
    manifest: dict[str, Any],
) -> SanitizationReport:
    """Write a sanitized copy of a project export archive.

    Files are recognized by their name, wherever they sit in the archive, so
    the function does not depend on the layout of the DSS export.

    :param source_path: path of the archive produced by DSS
    :param target_path: path of the sanitized archive to create
    :param redaction_mode: how project variables are treated (see settings)
    :param manifest: facts about the export, written at the root of the
        archive together with the sanitization report
    :returns: what was changed
    """
    report = SanitizationReport()

    with (
        zipfile.ZipFile(source_path, "r") as source,
        zipfile.ZipFile(target_path, "w", compression=zipfile.ZIP_DEFLATED) as target,
    ):
        for source_info in source.infolist():
            archive_path = source_info.filename

            if source_info.is_dir():
                _write_entry(target, source_info, b"")
                continue

            if archive_path == MANIFEST_FILE_NAME:
                # Never let an exported file pass for the audit manifest.
                report.files_dropped.append(archive_path)
                continue

            content = source.read(source_info)
            file_name = _file_name(archive_path)

            try:
                if file_name.endswith(NOTEBOOK_SUFFIX):
                    content, cells_cleared = clean_notebook(content)
                    report.notebooks_cleaned += 1
                    report.notebook_cells_cleared += cells_cleared
                elif file_name in VARIABLES_FILE_NAMES and redaction_mode != REDACT_NONE:
                    content, redacted_count = redact_variables(content, redaction_mode)
                    report.variables_files_redacted += 1
                    report.variable_values_redacted += redacted_count
            except UnreadableContent:
                report.files_dropped.append(archive_path)
                continue

            _write_entry(target, source_info, content)
            report.files_kept += 1

        full_manifest = dict(manifest)
        full_manifest["variablesRedaction"] = redaction_mode
        full_manifest["sanitization"] = report.to_dict()
        target.writestr(MANIFEST_FILE_NAME, _to_json_bytes(full_manifest))

    return report
