"""Plugin-level settings.

These values come from the plugin settings page, which only DSS administrators
can read and edit. Auditors cannot change them when they run a macro.
"""

from dataclasses import dataclass
from typing import Any, Optional

REDACT_ALL = "ALL"
REDACT_SECRET_KEYS = "SECRET_KEYS"
REDACT_NONE = "NONE"
VALID_REDACTION_MODES = (REDACT_ALL, REDACT_SECRET_KEYS, REDACT_NONE)

DEFAULT_AUDITOR_GROUP = "CDP_ADMIN_AUDIT"
DEFAULT_HUB_FOLDER = "audit_exports"
DEFAULT_MAX_PROJECTS_PER_RUN = 10


class SettingsError(Exception):
    """Raised when the plugin settings are missing or invalid."""


@dataclass(frozen=True)
class PluginSettings:
    """Validated plugin settings."""

    auditor_group: str
    hub_project_key: str
    hub_folder: str
    restrict_to_hub_project: bool
    variables_redaction: str
    max_projects_per_run: int
    admin_api_key: Optional[str]


def _read_text(plugin_config: dict[str, Any], name: str, default: str = "") -> str:
    """Return a setting as a stripped string, or the default when it is empty."""
    raw_value = plugin_config.get(name)
    if raw_value is None:
        return default
    text = str(raw_value).strip()
    if text == "":
        return default
    return text


def load_settings(plugin_config: dict[str, Any]) -> PluginSettings:
    """Build the validated settings from the raw plugin configuration.

    :param plugin_config: the dict DSS passes to the macro constructor
    :raises SettingsError: when a mandatory setting is missing or invalid
    """
    auditor_group = _read_text(plugin_config, "auditor_group", DEFAULT_AUDITOR_GROUP)
    hub_project_key = _read_text(plugin_config, "hub_project_key")
    hub_folder = _read_text(plugin_config, "hub_folder", DEFAULT_HUB_FOLDER)
    variables_redaction = _read_text(plugin_config, "variables_redaction", REDACT_ALL)
    admin_api_key = _read_text(plugin_config, "admin_api_key")

    if hub_project_key == "":
        raise SettingsError(
            "The hub project key is not set. Ask a DSS administrator to fill it "
            "in the settings of the CDP Audit Export plugin."
        )

    if variables_redaction not in VALID_REDACTION_MODES:
        raise SettingsError(
            f"Unknown variables redaction mode '{variables_redaction}'. "
            f"Expected one of {', '.join(VALID_REDACTION_MODES)}."
        )

    raw_max_projects = plugin_config.get("max_projects_per_run")
    if raw_max_projects is None or raw_max_projects == "":
        max_projects_per_run = DEFAULT_MAX_PROJECTS_PER_RUN
    else:
        try:
            max_projects_per_run = int(raw_max_projects)
        except (TypeError, ValueError) as error:
            raise SettingsError(
                f"'Max projects per run' must be a whole number, got '{raw_max_projects}'."
            ) from error
    if max_projects_per_run < 1:
        raise SettingsError("'Max projects per run' must be at least 1.")

    # The checkbox is only False when an administrator explicitly unchecked it.
    restrict_to_hub_project = plugin_config.get("restrict_to_hub_project") is not False

    return PluginSettings(
        auditor_group=auditor_group,
        hub_project_key=hub_project_key,
        hub_folder=hub_folder,
        restrict_to_hub_project=restrict_to_hub_project,
        variables_redaction=variables_redaction,
        max_projects_per_run=max_projects_per_run,
        admin_api_key=admin_api_key if admin_api_key != "" else None,
    )
