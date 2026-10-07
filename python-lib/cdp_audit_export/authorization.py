"""Authorization checks.

DSS cannot restrict a macro to one group, so the macros enforce the rule
themselves, before any privileged client is created.
"""

from typing import Any

from cdp_audit_export.settings import PluginSettings


class AccessDenied(Exception):
    """Raised when the caller is not allowed to run an audit macro."""


def get_login(auth_info: dict[str, Any]) -> str:
    """Return the login of the caller described by ``DSSClient.get_auth_info()``.

    :raises AccessDenied: when the identity cannot be determined
    """
    login = auth_info.get("authIdentifier")
    if not isinstance(login, str) or login.strip() == "":
        raise AccessDenied("The identity of the caller could not be determined.")
    return login


def require_auditor(auth_info: dict[str, Any], auditor_group: str) -> str:
    """Check that the caller belongs to the auditor group.

    Group names are compared exactly, as DSS group names are case sensitive.

    :param auth_info: result of ``DSSClient.get_auth_info()`` for the end user
    :param auditor_group: name of the DSS group allowed to run the macros
    :returns: the login of the caller
    :raises AccessDenied: when the caller is not a member of the group
    """
    login = get_login(auth_info)

    groups = auth_info.get("groups")
    if not isinstance(groups, list):
        groups = []

    if auditor_group not in groups:
        raise AccessDenied(
            f"User '{login}' is not a member of the '{auditor_group}' group. "
            "This macro is reserved to auditors."
        )
    return login


def require_hub_project(current_project_key: str, settings: PluginSettings) -> None:
    """Check that the macro runs from the hub project, when the rule is enabled.

    :param current_project_key: key of the project the macro was launched from
    :raises AccessDenied: when the macro runs from another project
    """
    if not settings.restrict_to_hub_project:
        return
    if current_project_key != settings.hub_project_key:
        raise AccessDenied(
            f"This macro can only be run from the '{settings.hub_project_key}' project."
        )
