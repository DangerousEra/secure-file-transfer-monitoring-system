# Presentation Demonstration Script

## Preparation

1. Install dependencies and run `python app.py`.
2. Open `http://127.0.0.1:5000`.
3. In Settings, select **Create demo environment**, then **Start**. This configures only synthetic folders beneath `data/demo_environment`.
4. Open a second terminal and run `python demo.py`.

## Narration and expected observable results

1. **Normal file creation:** Explain that `normal_note.txt` is created in `monitored`. Show its persisted create event.
2. **Sensitive movement:** Explain that `restricted_transfer.csv` is synthetic. It moves from `sensitive` to `restricted`. Show the policy violation alert with its source and destination paths.
3. **Integrity modification:** Explain that SFTMS records a SHA256 baseline, then changes the synthetic record. Click Verify all and show the mismatch.
4. **Protected deletion:** Show the `delete_me.txt` baseline and its deleted state after verification.
5. **Bulk activity:** Show the generated `bulk_demo_*.txt` activity in the USB simulation. The threshold is configurable in `.env`.
6. **Authorized movement:** Show the synthetic PDF in the authorized destination. Explain that an allowed destination avoids an unauthorized-movement alert.
7. **Audit report:** Open Reports and export CSV or PDF. State that exports only contain retained database information.

## Closing statement

SFTMS supports investigation of observable local activity. It does not assert malicious intent or intercept every file transfer.
