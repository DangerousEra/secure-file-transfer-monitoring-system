# Secure File Transfer Monitoring System

## Cover Page

**Academic Cybersecurity Project**  
**Project:** Secure File Transfer Monitoring System (SFTMS)  
**Prepared by:** [Student name]  
**Institution:** [Institution name]  
**Submission date:** [Date]

## Abstract

SFTMS is a local Flask application that observes filesystem changes in user-selected folders, records metadata in SQLite, applies explicit sensitivity and destination policies, maintains SHA256 integrity baselines, and presents alerts and audit reports. The project demonstrates defensive monitoring without claiming that every file copy, process, or cloud transfer can be observed.

## Introduction

File transfers are necessary for daily work but can expose confidential records when files move to unapproved folders, removable drives, network shares, or synchronization clients. A local monitor helps an analyst investigate observable changes and retain an audit trail.

## Problem Statement

Organizations need a practical way to record local file changes, identify policy-defined sensitive movement, and detect unexpected changes to protected files without collecting file contents.

## Practical Motivation

The project demonstrates endpoint-level defensive engineering: event capture, explainable rules, integrity verification, analyst workflow, and exportable evidence.

## Project Objectives

SFTMS records real Watchdog events, evaluates sensitive file movement against rules, verifies SHA256 baselines, creates deduplicated alerts, preserves data in SQLite, and provides browser-based review and reporting.

## Scope of the Project

The scope covers local folders selected by the user. It includes synthetic USB and cloud-sync folders for classroom testing. It excludes packet inspection, content extraction, remote endpoint agents, prevention, and forensic recovery.

## Existing System and Its Limitations

Manual file review lacks timely history and makes correlation difficult. Operating-system auditing can be comprehensive but often needs administrative configuration and produces large volumes. Generic file browsers do not apply a local transfer policy or integrity baseline.

## Proposed System

SFTMS schedules Watchdog observers for configured folders. The event handler normalizes callbacks, gathers safe metadata, evaluates classification and policies, persists the result, verifies protected paths, and creates alerts when needed.

## Technology Stack

Python 3.11+, Flask, Watchdog, hashlib, SQLite, ReportLab, HTML/CSS/JavaScript, Bootstrap, Chart.js, pytest, and python-dotenv form the stack. The username is recorded; source-process attribution is marked unavailable because Watchdog callbacks do not reliably identify it.

## System Architecture

The layers are the web UI, REST routes with CSRF checks, monitoring and policy services, SQLite storage, and report export. Detailed diagrams appear in `ARCHITECTURE.md`.

## Module Description

- `monitor.py` owns observer lifecycle.
- `event_handler.py` converts callbacks to records and correlates short-lived duplicates.
- `classifier.py` identifies configured sensitive folders and extensions.
- `policy_engine.py` evaluates allowed and restricted destination rules.
- `integrity.py` records and verifies chunked SHA256 values.
- `alert_manager.py` creates minute-bucket deduplicated alerts.
- `report_generator.py` exports persisted events and alerts to CSV and PDF, with severity counts in the PDF.

## Detailed Working Methodology

The user configures existing folders. The service starts an observer per enabled folder. On a callback, SFTMS preserves source and destination when the OS exposes them, hashes safe-sized files, records an event, applies policy, checks protected files, and queues relevant alerts.

## File System Monitoring

Watchdog detects create, modify, delete, and move callbacks for files and directories. Copy is not a universal native event; a resulting creation is recorded and move correlations use only observable source and destination data.

## Sensitive File Detection

Sensitivity is rule-based, not a claim about content. Default extensions include PDF, Office documents, CSV, SQL, database, key, environment, and configuration files. A directory whose label begins with “Sensitive” also makes its descendants sensitive.

## Unauthorized File Movement Detection

A policy states source folder, extensions, allowed paths, restricted paths, severity, and enabled state. A restricted destination match creates a policy violation alert. An allowed match records an authorized result. A sensitive move without a matching rule requires investigation.

## SHA256 Integrity Verification

When a file becomes protected, SFTMS stores its baseline SHA256. Verification recalculates the hash in chunks. Matching values are Verified, differing values are Mismatch, absent files are Deleted, and inaccessible paths remain Pending Verification.

## Security Alert Mechanism

Policies, integrity mismatches, deletions, bulk activity, and handler exceptions can create alerts. A title, file, paths, rule, severity, and status are stored. A time-bucketed key suppresses immediate duplicates. Analysts update investigation status and notes.

## Database Design

The database uses `monitoring_directories`, `security_policies`, `file_events`, `integrity_records`, `security_alerts`, and `application_settings`. `security_alerts.related_event_id` relates an alert to a retained event where available. All values use parameterized queries.

## API Design

GET endpoints supply dashboard values, lists, settings, and report downloads. State-changing endpoints use POST, PUT, PATCH, or DELETE and require a same-session `X-CSRF-Token`. The local UI obtains this token from its Flask session.

## User Interface Description

The dark SOC-oriented dashboard presents actual database totals, Chart.js visualizations, recent events, monitor state, policies, integrity baselines, report controls, and investigation actions. It communicates detection boundaries in the UI and documentation.

## Implementation Details

The monitor runs in Watchdog background threads so the Flask request thread remains responsive. SQLite connections are opened per operation, foreign keys are enabled, transactions commit atomically, and callbacks catch exceptions to preserve the monitoring service.

## Testing Methodology

The pytest suite creates isolated temporary files and SQLite databases. It tests hash calculation, mismatch and deletion handling, classification, restricted and allowed movement, path-boundary behavior, bulk create alerts, database deduplication, alert updates, CSRF, cloud-demo read-only behavior, routes, report contents, and CSV formula escaping.

## Demonstration Scenarios

`demo.py` uses only `data/demo_environment`. Its scenarios cover normal creation, restricted sensitive transfer, integrity modification, protected deletion, threshold bulk activity, and authorized transfer. See `DEMO_SCRIPT.md` for presenter steps.

## Expected and Actual Outputs

Expected output is an event row for every callback that Watchdog delivers, with alert rows for defined boundary and integrity conditions. Actual output varies slightly by platform timing and event coalescing. The dashboard reports the persisted result and does not generate fabricated monitoring records.

## Results and Observations

The application provides a traceable local event history and allows repeatable policy and integrity demonstrations. Rule clarity matters: classification results reflect folder and extension configuration, not an assertion that a file’s content is confidential or malicious.

## Limitations

The system cannot guarantee process attribution or detect every copy/upload. It does not parse content or operate across hosts. The complete boundaries appear in `LIMITATIONS.md`.

## Future Enhancements

Possible improvements include authenticated multi-user roles, signed baselines, operating-system audit adapters, a message queue, tamper-evident log chaining, configurable retention jobs, richer copy correlation, and a centralized multi-host collector.

## Conclusion

SFTMS demonstrates a careful local monitoring approach: observable filesystem events, transparent classification, policy-aware alerts, SHA256 verification, persistent evidence, and reproducible testing. Its stated limitations prevent overclaiming detection capability.

## References

1. Python `hashlib` documentation.
2. Watchdog project documentation.
3. Flask documentation.
4. SQLite documentation.
5. NIST Computer Security Incident Handling Guide, SP 800-61 Rev. 2.
