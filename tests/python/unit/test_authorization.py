import pytest

from cdp_audit_export.authorization import AccessDenied, require_auditor, require_hub_project
from cdp_audit_export.settings import load_settings


def test_member_of_the_group_is_accepted():
    auth_info = {"authIdentifier": "jane", "groups": ["readers", "CDP_ADMIN_AUDIT"]}
    assert require_auditor(auth_info, "CDP_ADMIN_AUDIT") == "jane"


@pytest.mark.parametrize(
    "groups",
    [[], ["readers"], ["cdp_admin_audit"], ["CDP_ADMIN_AUDIT_EXTRA"], None, "CDP_ADMIN_AUDIT"],
)
def test_non_member_is_refused(groups):
    auth_info = {"authIdentifier": "bob", "groups": groups}
    with pytest.raises(AccessDenied, match="not a member"):
        require_auditor(auth_info, "CDP_ADMIN_AUDIT")


def test_missing_groups_entry_is_refused():
    with pytest.raises(AccessDenied, match="not a member"):
        require_auditor({"authIdentifier": "api-key-id"}, "CDP_ADMIN_AUDIT")


@pytest.mark.parametrize("auth_info", [{}, {"authIdentifier": ""}, {"authIdentifier": None}])
def test_unknown_identity_is_refused(auth_info):
    with pytest.raises(AccessDenied, match="identity"):
        require_auditor(auth_info, "CDP_ADMIN_AUDIT")


def test_hub_project_rule(plugin_config):
    settings = load_settings(plugin_config)

    require_hub_project("AUDIT_HUB", settings)
    with pytest.raises(AccessDenied, match="AUDIT_HUB"):
        require_hub_project("SALES", settings)


def test_hub_project_rule_can_be_disabled(plugin_config):
    plugin_config["restrict_to_hub_project"] = False
    require_hub_project("SALES", load_settings(plugin_config))
