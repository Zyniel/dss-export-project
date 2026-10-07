"""Macro "Audit: export project metadata".

Thin entry point: all the logic lives in the ``cdp_audit_export`` library.
"""

import dataiku
from dataiku.runnables import Runnable

from cdp_audit_export.export_service import parse_project_keys, run_export
from cdp_audit_export.report import render_export_report


class AuditExportProjectRunnable(Runnable):
    """Export the metadata of the requested projects into the audit hub folder."""

    def __init__(self, project_key, config, plugin_config):
        """Keep what DSS passes to the macro.

        :param project_key: key of the project the macro is launched from
        :param config: values of the macro parameters
        :param plugin_config: plugin settings, managed by the administrators
        """
        self.project_key = project_key
        self.config = config
        self.plugin_config = plugin_config

    def get_progress_target(self):
        """Report the progress as a number of projects."""
        requested_keys = parse_project_keys(self.config.get("project_keys"))
        return (max(len(requested_keys), 1), "NONE")

    def run(self, progress_callback):
        """Run the export and return the HTML report."""
        export_run = run_export(
            user_client=dataiku.api_client(),
            current_project_key=self.project_key,
            plugin_config=self.plugin_config,
            raw_project_keys=self.config.get("project_keys"),
            progress_callback=progress_callback,
        )
        return render_export_report(export_run)
