# Technical Project Video Script

## Opening

“This project is the Secure File Transfer Monitoring System. It monitors selected local folders, records filesystem events, applies file-movement policies, and verifies protected files with SHA256.”

## Problem and motivation

“Sensitive documents can leave approved areas through routine file operations. Manual review lacks an audit trail. The project provides local visibility without reading or storing document contents.”

## Architecture and stack

“Flask provides the local dashboard and API. Watchdog observes filesystem changes. SQLite stores metadata, policies, alerts, and integrity records. The integrity module uses Python’s hashlib SHA256 implementation.”

## How monitoring works

“The user adds permitted folders and starts the monitoring service. Watchdog sends callbacks for creations, modifications, deletions, and moves. SFTMS normalizes each callback, records safe metadata, and evaluates rules in the background.”

## Sensitive files and policies

“Sensitivity comes from transparent directory and extension rules. A policy identifies a source folder, restricted and allowed destinations, file extensions, and severity. A restricted match produces a policy violation that requires investigation rather than a claim of malicious behavior.”

## SHA256 integrity

“When a user protects a file, SFTMS records a SHA256 baseline. Verification compares a fresh hash with that baseline. The status becomes Verified, Mismatch, Deleted, or Pending Verification.”

## Dashboard walkthrough

“The dashboard shows database-backed totals, charts, recent activity, monitor status, policies, alerts, integrity records, and report controls.”

## Live demonstration

“I now run the safe demo. It creates synthetic files only. I will show normal creation, a restricted transfer, an integrity mismatch, deletion, bulk activity, and an authorized transfer.”

## Testing, limits, and conclusion

“The pytest suite covers integrity, classification, policies, persistence, alerts, APIs, and report generation. Watchdog cannot reliably name every source process or observe every copy and cloud upload. The project clearly presents those limits while providing a functional local defensive-monitoring demonstration.”
