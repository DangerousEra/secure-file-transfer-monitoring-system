# User Guide

## Starting the system

Install the requirements, then run `python app.py`. The dashboard opens at `http://127.0.0.1:5000` and binds only to the local computer.

## Configuring directories

1. Open **Settings & Monitoring**.
2. Add an existing non-root directory. Use a label beginning with “Sensitive” to classify files in it as sensitive.
3. Add any permitted destinations such as a dedicated USB or cloud-sync simulation folder.
4. Select **Start**. Restart the service whenever the directory list changes.

## Adding a policy

Open **Policies**, select **New policy**, and set a source folder, restricted destinations, optional allowed destinations, extensions, and severity. A policy indicates a boundary to investigate, not proof of malicious activity.

## Integrity monitoring

Open **Integrity Monitor** and provide the path to an existing local file. SFTMS records a SHA256 baseline. Select **Verify all** to compare current values; deletion and mismatches create alerts.

## Investigating alerts

Open **Security Alerts**, filter the queue, select **Update**, and record investigation notes. The status may be New, Investigating, Resolved, or False Positive.

## Reporting

Open **Reports**, optionally select a date range, then download CSV or PDF. Both formats include persisted file events and alert details; CSV text that could be interpreted as a spreadsheet formula is escaped. Reports use persisted facts only.

## Safe demo

Run `python demo.py`. It works only under `data/demo_environment` and creates no real credentials or personal documents.
