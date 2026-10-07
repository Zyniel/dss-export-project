import pytest

from cdp_audit_export.settings import SettingsError, load_settings


def test_defaults_apply_when_only_the_hub_project_is_set():
    settings = load_settings({"hub_project_key": " AUDIT_HUB "})

    assert settings.auditor_group == "CDP_ADMIN_AUDIT"
    assert settings.hub_project_key == "AUDIT_HUB"
    assert settings.hub_folder == "audit_exports"
    assert settings.restrict_to_hub_project is True
    assert settings.variables_redaction == "ALL"
    assert settings.max_projects_per_run == 10
    assert settings.admin_api_key is None


def test_explicit_values_are_kept(plugin_config):
    plugin_config["restrict_to_hub_project"] = False
    plugin_config["variables_redaction"] = "SECRET_KEYS"
    plugin_config["admin_api_key"] = "s3cr3t"

    settings = load_settings(plugin_config)

    assert settings.restrict_to_hub_project is False
    assert settings.variables_redaction == "SECRET_KEYS"
    assert settings.max_projects_per_run == 2
    assert settings.admin_api_key == "s3cr3t"


def test_missing_hub_project_is_rejected():
    with pytest.raises(SettingsError, match="hub project key"):
        load_settings({"hub_project_key": "  "})


def test_unknown_redaction_mode_is_rejected(plugin_config):
    plugin_config["variables_redaction"] = "SOME"
    with pytest.raises(SettingsError, match="redaction mode"):
        load_settings(plugin_config)


@pytest.mark.parametrize("bad_value", ["ten", 0, -3])
def test_invalid_project_limit_is_rejected(plugin_config, bad_value):
    plugin_config["max_projects_per_run"] = bad_value
    with pytest.raises(SettingsError, match="Max projects per run"):
        load_settings(plugin_config)
