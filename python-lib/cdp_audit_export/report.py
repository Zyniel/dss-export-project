"""HTML report shown to the auditor at the end of an export run."""

import html

from cdp_audit_export.export_service import STATUS_OK, ExportResult, ExportRun

TABLE_STYLE = "border-collapse: collapse; margin-top: 12px;"
CELL_STYLE = "border: 1px solid #ccc; padding: 6px 10px; text-align: left; vertical-align: top;"


def format_size(size_in_bytes: int) -> str:
    """Format a size in bytes for a human reader."""
    if size_in_bytes < 1024:
        return f"{size_in_bytes} B"
    if size_in_bytes < 1024 * 1024:
        return f"{size_in_bytes / 1024:.1f} KB"
    return f"{size_in_bytes / (1024 * 1024):.1f} MB"


def describe_result(result: ExportResult) -> str:
    """Summarize, as HTML, what happened to one project."""
    if result.status != STATUS_OK:
        return html.escape(result.error or "Unknown error")

    details = []
    if result.report is not None:
        details.append(f"{result.report.files_kept} files")
        details.append(
            f"{result.report.notebooks_cleaned} notebook(s) cleaned "
            f"({result.report.notebook_cells_cleared} cell output(s) removed)"
        )
        details.append(f"{result.report.variable_values_redacted} variable value(s) redacted")
        if len(result.report.files_dropped) > 0:
            dropped_files = ", ".join(result.report.files_dropped)
            details.append(f"dropped as unreadable: {dropped_files}")
    return html.escape("; ".join(details))


def render_export_report(run: ExportRun) -> str:
    """Build the HTML report of an export run.

    Every value coming from DSS or from the auditor is escaped.
    """
    folder_url = (
        f"/projects/{html.escape(run.hub_project_key, quote=True)}"
        f"/managedfolder/{html.escape(run.hub_folder_id, quote=True)}/view/"
    )

    succeeded_count = 0
    for result in run.results:
        if result.status == STATUS_OK:
            succeeded_count += 1

    lines = []
    lines.append("<div>")
    lines.append(
        f"<p><strong>{succeeded_count} of {len(run.results)} project(s) exported</strong> "
        f"for {html.escape(run.requester)}.</p>"
    )
    lines.append(
        f'<p>The archives are in the folder <a href="{folder_url}" target="_blank">'
        f"{html.escape(run.hub_folder_name)}</a> of the project "
        f"{html.escape(run.hub_project_key)}.</p>"
    )
    lines.append(f'<table style="{TABLE_STYLE}">')
    lines.append(
        "<tr>"
        f'<th style="{CELL_STYLE}">Project</th>'
        f'<th style="{CELL_STYLE}">Status</th>'
        f'<th style="{CELL_STYLE}">Archive in the folder</th>'
        f'<th style="{CELL_STYLE}">Size</th>'
        f'<th style="{CELL_STYLE}">Details</th>'
        "</tr>"
    )
    for result in run.results:
        archive_path = html.escape(result.archive_path or "")
        archive_size = format_size(result.archive_size) if result.archive_path else ""
        lines.append(
            "<tr>"
            f'<td style="{CELL_STYLE}">{html.escape(result.project_key)}</td>'
            f'<td style="{CELL_STYLE}">{html.escape(result.status)}</td>'
            f'<td style="{CELL_STYLE}">{archive_path}</td>'
            f'<td style="{CELL_STYLE}">{archive_size}</td>'
            f'<td style="{CELL_STYLE}">{describe_result(result)}</td>'
            "</tr>"
        )
    lines.append("</table>")
    lines.append(
        "<p>Each archive holds project metadata only: no dataset data, no folder "
        "content, no Git history, no notebook output.</p>"
    )
    lines.append("</div>")
    return "\n".join(lines)
