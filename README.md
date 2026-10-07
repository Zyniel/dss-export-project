# CDP Audit Export

Dataiku DSS plugin that lets the members of an audit group (`CDP_ADMIN_AUDIT` by default)
export the **metadata** of any project, without holding any advanced permission on it.

The export runs with an administrative identity, is stripped of anything that is not
metadata, and is delivered in a managed folder of a hub project the auditors can read.

Built for DSS 13.2.4 and Python 3.9. Standard library only: no code environment needed.

## What auditors get

Two macros, available from the **Macros** menu of the hub project:

| Macro | What it does |
|---|---|
| **Audit: list projects** | Table of every project of the instance (key, name, owner). |
| **Audit: export project metadata** | Exports the given project keys and returns a report with a link to the folder. |

Each export produces one archive in the hub folder:

```
/<PROJECT_KEY>/<PROJECT_KEY>__<UTC timestamp>__<requester>.zip
```

The archive is the DSS project export with:

- every data option of the export disabled (datasets, uploads, managed folders, models,
  evaluation stores, insights data, Git history);
- the cell outputs of Jupyter notebooks removed;
- the values of project variables redacted (names are kept);
- an `audit-manifest.json` at its root: project, requester, time, node, export options
  and what the sanitization changed.

A file that should be cleaned but cannot be parsed is left out of the archive and listed
in the manifest and in the report.

## How access is controlled

1. The macro reads the identity of the caller with the caller's own client.
2. It refuses the run unless the caller belongs to the auditor group and, by default,
   unless it was launched from the hub project.
3. Only then does it create a privileged client, which never leaves the macro.
4. Every request, successful or failed, writes a JSON record under `/_requests/` in the
   hub folder (requester, project, time, status, archive path). Auditors only have read
   access to that folder.

DSS plugin permissions can hide the macros from other groups, but Dataiku documents them
as a visibility setting only. The checks above are what protects the export.

## Setup (once per node)

1. **Install the plugin** from the zip (Plugins > Add plugin > Upload).
2. **Create the hub project**, for instance `AUDIT_HUB`, with a managed folder named
   `audit_exports`.
3. **Grant the auditor group** "Read project content" on the hub project. Nothing else,
   on no other project.
4. **Hide the macros from other users** (optional): in the permissions of the plugin,
   uncheck the default permission and grant access to the auditor group.
5. **Fill the plugin settings** (Plugins > CDP Audit Export > Settings):

| Setting | Default | Meaning |
|---|---|---|
| Auditor group | `CDP_ADMIN_AUDIT` | DSS group allowed to run the macros. |
| Only run from the hub project | on | Refuse runs launched from another project. |
| Max projects per run | 10 | Upper limit of one macro run. |
| Hub project key | none | Project that receives the archives. Mandatory. |
| Hub managed folder | `audit_exports` | Name or id of the folder in the hub project. |
| Project variables | Redact every value | `Redact every value`, `Redact values of secret-looking names only` or `Keep values`. |
| Admin API key | empty | Only if the DSS helper cannot be used (see below). |

Plugin settings are only visible to DSS administrators.

To read the request records as a dataset, create a "Files in folder" dataset on the hub
folder, restricted to the `_requests` path, with the JSON format.

## First-run checklist

The library is covered by unit tests, but the plugin has not been run against a live DSS
instance. Check these points on a test node before opening it to auditors.

1. **Privileged client.** Run "Audit: list projects" as an auditor. The plugin relies on
   `dataiku.runnables.utils.get_admin_dss_client`, which Dataiku documents for project
   creation macros. If it fails in this macro, create a global admin API key and put it
   in the "Admin API key" setting.
2. **Generated API keys.** After a few runs, look at Administration > Security > Global
   API keys. If the helper leaves one key per run, switch to the "Admin API key" setting.
3. **Archive content.** Export a test project that has a notebook with outputs, project
   variables, an uploaded dataset and a managed folder with files. Open the archive:
   - no dataset or folder content;
   - `audit-manifest.json` reports at least one notebook cleaned and one variable redacted.
     Zero would mean that DSS names those files differently from what
     `sanitizer.py` expects (`*.ipynb`, `variables.json`, `localvariables.json`).
4. **Refusals.** Run the macro as a user outside the group, and from another project:
   both must be refused.

## Known limits

- **Hardcoded secrets are not detected.** A password written in a code recipe, a scenario
  step or a webhook URL stays in the archive.
- **Variables redaction is by file name.** Any file named `variables.json` or
  `localvariables.json` in the export is redacted, wherever it sits.
- With "Redact every value", analysis tools cannot resolve `${variable}` references in
  table names. Switch to "secret-looking names only" if lineage needs them.
- The archive is meant for analysis. Do not re-import it in DSS.

## Development

```
uv venv --python 3.9 .venv
uv pip install --python .venv/bin/python pytest ruff mypy "dataiku-api-client==13.2.4"
.venv/bin/ruff format . && .venv/bin/ruff check .
.venv/bin/mypy
.venv/bin/python -m pytest
```

Layout:

```
plugin.json                               plugin descriptor and settings
python-lib/cdp_audit_export/
    settings.py                           plugin settings, validated
    authorization.py                      group and hub project checks
    sanitizer.py                          archive cleaning (no DSS dependency)
    export_service.py                     orchestration, the only module calling DSS
    report.py                             HTML report
python-runnables/audit-export-project/    macro "Audit: export project metadata"
python-runnables/audit-list-projects/     macro "Audit: list projects"
tests/python/unit/                        unit tests, with fakes of the DSS objects
```
