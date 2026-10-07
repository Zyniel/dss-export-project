from cdp_audit_export.export_service import ExportResult, ExportRun
from cdp_audit_export.report import format_size, render_export_report
from cdp_audit_export.sanitizer import SanitizationReport


def build_run():
    report = SanitizationReport(
        files_kept=42,
        notebooks_cleaned=3,
        notebook_cells_cleared=12,
        variable_values_redacted=5,
        files_dropped=["project_config/ipython_notebooks/<b>.ipynb"],
    )
    return ExportRun(
        requester="jane<script>",
        hub_project_key="AUDIT_HUB",
        hub_folder_id="aBcD1234",
        hub_folder_name="audit_exports",
        results=[
            ExportResult("SALES", "OK", "/SALES/SALES__x.zip", 2048, report),
            ExportResult("RISK", "FAILED", error="RuntimeError: <boom>"),
        ],
    )


def test_report_summarizes_the_run():
    page = render_export_report(build_run())

    assert "1 of 2 project(s) exported" in page
    assert 'href="/projects/AUDIT_HUB/managedfolder/aBcD1234/view/"' in page
    assert "/SALES/SALES__x.zip" in page
    assert "2.0 KB" in page
    assert "3 notebook(s) cleaned (12 cell output(s) removed)" in page
    assert "5 variable value(s) redacted" in page


def test_report_escapes_untrusted_values():
    page = render_export_report(build_run())

    assert "<script>" not in page
    assert "<boom>" not in page
    assert "<b>.ipynb" not in page
    assert "RuntimeError: &lt;boom&gt;" in page


def test_size_formatting():
    assert format_size(512) == "512 B"
    assert format_size(2048) == "2.0 KB"
    assert format_size(5 * 1024 * 1024) == "5.0 MB"
