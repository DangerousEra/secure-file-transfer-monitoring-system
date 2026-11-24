# Testing Report

## Method

Run `python -m pytest -q` from the project root. Tests use `tmp_path` for an isolated SQLite database and synthetic files. No test reads, writes, or deletes user files.

## Test cases

| Area | Test | Expected result |
|---|---|---|
| Integrity | SHA256 generation | 64-character digest is returned |
| Integrity | Modified protected file | Status changes to `Mismatch` |
| Integrity | Deleted protected file | Status changes to `Deleted` |
| Classification | `.key` file | Sensitive and High |
| Classification | `.txt` file | Normal |
| Policy | Sensitive CSV to restricted folder | Policy Violation, High |
| Policy | Sensitive CSV to allowed folder | Authorized |
| Policy | Allowed path with a similarly named sibling | Sibling is not authorized by the path rule |
| Monitoring | Bulk file creation in a monitored folder | Bulk activity alert is generated |
| Database | Repeated event key | Duplicate insert is rejected |
| Alerts | Status update | Investigation status persists |
| API | Dashboard and pages | HTTP 200 |
| API | State change without token | HTTP 403 |
| Reports | CSV and PDF endpoints | Download response succeeds |
| Reports | CSV alert rows and formula-like filenames | Alerts are included and spreadsheet formulas are neutralized |

## Actual results

The latest verification completed with **15 passed** using `python -m pytest -q --basetemp .test-tmp`. Automated page checks covered the dashboard, activity, alerts, integrity, policies, reports, and settings pages. Tests also cover cloud-demo write blocking, bulk create alerts, path-component boundaries, report alert rows, and CSV formula escaping.

A clean synthetic Watchdog run recorded **52 events, 3 alerts, 2 integrity violations, and 6 configured directories**. The evidence files in `evidence/` contain its console log, dashboard summary, and downloaded CSV/PDF reports.

## Manual checks

1. Start the application and open each navigation page.
2. Create the synthetic demo environment.
3. Start monitoring and run `python demo.py` in a separate local terminal.
4. Inspect events, alerts, integrity state, CSV export, and PDF export.
5. Stop the service and confirm state changes in Settings.
