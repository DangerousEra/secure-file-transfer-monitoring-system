# Detection Boundaries and Limitations

- Watchdog reports local filesystem changes but does not reliably name the process responsible. SFTMS marks process attribution as unavailable rather than guessing.
- A copy can appear as a creation event at the destination without a linked source event. A native move usually provides source and destination, but event semantics depend on the OS and filesystem. This version does not claim to intercept every copy, upload, download, or cloud synchronization action.
- Read/access events are not observed. Event-time hashes are snapshots after callbacks, not correlated before-and-after transfer hashes. Integrity comparison is available for files explicitly given a stored baseline.
- USB, network-share, and cloud detection works only for folders that the user explicitly configures and that the local process can observe. The provided USB and cloud locations are safe simulations.
- Quick repeated updates can be coalesced by the operating system. The handler also deduplicates near-identical callbacks to avoid noisy duplicate logs.
- SHA256 comparison detects content change to a protected file after a baseline. It cannot explain who changed a file, recover deleted content, or verify a file that is inaccessible.
- Files over 100 MB record size without an event-time hash to keep callbacks responsive. Manual integrity verification hashes protected files in chunks.
- Policy matching uses normalized local paths and configured prefixes. It does not parse archive contents, inspect file contents, or prevent data loss.
- SQLite is appropriate for this local academic project, not a multi-host enterprise collection platform.
- The UI has same-session CSRF checks and localhost binding, but it is not a replacement for authentication, endpoint protection, or a production SIEM.
- The public cloud demonstration is read-only and uses synthetic data. It does not provide user authentication or support monitoring a visitor's local files.
