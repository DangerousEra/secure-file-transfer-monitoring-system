# Secure File Transfer Monitoring System (SFTMS)

SFTMS is a local-first academic cybersecurity project that uses Watchdog to record filesystem changes in folders selected by the user. It applies transparent sensitivity and policy rules, maintains SHA256 integrity baselines, stores activity in SQLite, presents a Flask dashboard, and exports database-backed audit reports.

## Safety and detection boundary

The application records metadata and hashes only. It never uploads, deletes, encrypts, or edits a monitored file. It binds to `127.0.0.1` by default.

Watchdog tells the application that a filesystem event occurred. It does not consistently identify the originating process, cloud upload, download, USB device, or every copy operation. SFTMS therefore labels movement as *suspicious*, *policy violation*, or *requires investigation*, and records process attribution as unavailable where the platform cannot provide it. See `docs/LIMITATIONS.md`.

## Setup

Requirements: Python 3.11 or newer.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python app.py
```

Open `http://127.0.0.1:5000`. Add one or more existing folders under **Settings**, then select **Start**. Restart monitoring after changing the directory list.

## Safe classroom demonstration

The demo creates only synthetic files beneath `data/demo_environment`:

```powershell
python demo.py
```

It exercises normal creation, a restricted transfer, an integrity mismatch, protected-file deletion, bulk activity, and an authorized transfer. The dashboard reflects what Watchdog observed on the local filesystem; event timing can vary slightly by operating system.

## Tests

```powershell
python -m pytest -q
```

## Reports

Use the **Reports** page to export CSV or PDF. Both formats use persisted SQLite data and include no invented events.

A clean synthetic monitoring run and its CSV/PDF report evidence are saved in `docs/evidence/`.

## Project layout

`core/` contains monitoring, integrity, classification, policies, alerts, reports, and process-context services. `database/` contains the schema and repository. `api/` holds routes, `templates/` and `static/` implement the dashboard, `tests/` contains pytest coverage, and `docs/` contains the academic material.

## Publication and deployment

Review `.gitignore`, never commit `.env`, SQLite databases, generated reports, real keys, or personal files. A normal cloud-hosted dashboard cannot monitor a visitor’s local filesystem; filesystem monitoring runs on the machine that runs `python app.py`. For a cloud demo, label it as synthetic data only.

### Render demonstration deployment

This repository includes `render.yaml` for a public **synthetic demonstration**. Push the repository to GitHub, create a Render account, choose **New > Blueprint**, select the repository, and approve the generated `secure-file-transfer-monitor-demo` service. Render installs `requirements.txt` and runs `gunicorn --bind 0.0.0.0:$PORT app:app`. The resulting `https://...onrender.com` URL is suitable for the submission form after you verify it. Create the demo environment from Settings only; never upload or configure personal files in the cloud demo.
