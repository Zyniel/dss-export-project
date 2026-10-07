"""Macro "Audit: list projects".

Thin entry point: all the logic lives in the ``cdp_audit_export`` library.
"""

import dataiku
from dataiku.runnables import ResultTable, Runnable

from cdp_audit_export.export_service import list_projects


class AuditListProjectsRunnable(Runnable):
    """List every project of the instance, for auditors to pick from."""

    def __init__(self, project_key, config, plugin_config):
        """Keep what DSS passes to the macro.

        :param project_key: key of the project the macro is launched from
        :param config: values of the macro parameters (none for this macro)
        :param plugin_config: plugin settings, managed by the administrators
        """
        self.project_key = project_key
        self.config = config
        self.plugin_config = plugin_config

    def get_progress_target(self):
        """No progress bar: the listing is a single call."""
        return None

    def run(self, progress_callback):
        """Return the table of projects."""
        rows = list_projects(
            user_client=dataiku.api_client(),
            current_project_key=self.project_key,
            plugin_config=self.plugin_config,
        )

        result_table = ResultTable()
        result_table.add_column("project_key", "Project key", "STRING")
        result_table.add_column("name", "Name", "STRING")
        result_table.add_column("owner", "Owner", "STRING")
        for row in rows:
            result_table.add_record([row["projectKey"], row["name"], row["owner"]])
        return result_table
