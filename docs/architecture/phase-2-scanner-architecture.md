# SentinelDLP — Phase 2 Architecture: File Scanning Engine & Inventory System

## 1. Overview & Cybersecurity Mission

In enterprise Data Loss Prevention (DLP) and exfiltration detection, building an accurate, trustworthy **File Inventory** is the prerequisite for any sensitive data classification or exfiltration monitoring:
- A defensive security scanner must **never** modify, delete, upload, or execute target files.
- It must enforce **strict directory allowlisting** to prevent unauthorized enumeration of sensitive host filesystems (e.g., operating system files, user profiles, or network shares).
- It must defend against **directory traversal** (`..` sequences) and **symlink/junction escape attacks**.
- It must compute cryptographic **SHA-256 digests** via chunked streaming to prevent high memory consumption on large files.
- It must cross-reference file extensions against **magic byte content signatures** to identify disguised or spoofed files.

---

## 2. Module Architecture

```
SentinelDLP Scanner Core (`backend/app/scanner/`)
├── validators.py       # Canonical path resolution & boundary escape prevention
├── discovery.py        # Recursive directory traversal with exclusion filters & cancellation
├── filetypes.py        # Extension & magic-byte classification & discrepancy flags
├── hashing.py          # Memory-safe 64KB chunk streaming SHA-256 calculation
├── metadata.py         # Cross-platform timestamps & privacy-preserving relative paths
├── schemas.py          # Pydantic schemas for requests, summaries, and paginated inventory
└── engine.py           # Background execution coordinator with thread safety & cancellation
```

---

## 3. Supported File Types & Signature Matrix

| Type Key | Category | Supported Extensions | Expected Content Signature / Magic Bytes |
|---|---|---|---|
| `pdf` | Document | `.pdf` | `b"%PDF-"` |
| `docx` | Document | `.docx` | `b"PK\x03\x04"` (OpenXML archive) |
| `txt` | Document | `.txt`, `.text`, `.log`, `.md` | Plain text / UTF-8 |
| `csv` | Structured Data | `.csv`, `.tsv` | Plain text / Delimited tabular |
| `json` | Structured Data | `.json` | Text starting with `{` or `[` |
| `xml` | Structured Data | `.xml` | Text starting with `<?xml` or `<` |
| `py` | Source Code | `.py`, `.pyw` | Python syntax |
| `js` | Source Code | `.js`, `.mjs`, `.cjs` | JavaScript syntax |
| `ts` | Source Code | `.ts`, `.tsx` | TypeScript syntax |
| `java` | Source Code | `.java` | Java source syntax |
| `env` | Configuration | `.env`, `.env.example`, etc. | Key-value configuration syntax |
| `yaml` | Configuration | `.yaml`, `.yml` | YAML syntax |
| `sql` | Structured Data | `.sql` | SQL DDL/DML syntax |
| `png` | Image | `.png` | `b"\x89PNG\r\n\x1a\n"` |
| `jpg` | Image | `.jpg`, `.jpeg` | `b"\xff\xd8\xff"` |
| `zip` | Archive | `.zip` | `b"PK\x03\x04"`, `b"PK\x05\x06"` |

### Signature Discrepancy Detection (`type_mismatch`)
When a file extension declares a binary format (e.g. `.pdf` or `.png`) but the file lacks the requisite magic number bytes, the scanner marks `type_mismatch = True`. This highlights potential malware staging, file disguising, or extension spoofing for security analysts.

---

## 4. Security Bounds & Controls

1. **Explicit Root Allowlist**: The backend only scans pre-approved directory roots defined in `Settings.get_authorized_roots()`. Unapproved paths return HTTP 403 Forbidden.
2. **Canonical Path Checking**: Resolves all symlinks and relative references via `os.path.realpath`. Traversal sequences attempting to reach parent folders are blocked before disk reads.
3. **Symlink Escape Defense**: Uses `followlinks=False` during traversal. Any symlink resolving outside the authorized root boundary is logged as an escape attempt and skipped.
4. **Safety Limits**:
   - `MAX_FILES_PER_SCAN`: 10,000 files ceiling.
   - `MAX_FILE_SIZE_BYTES`: 100 MB per file limit.
   - `MAX_SCAN_DURATION_SECONDS`: 300 seconds wall-clock timeout.
5. **Real-time Cancellation**: Every scan job registers a `threading.Event` cancellation token, allowing immediate user-requested aborts via `POST /api/v1/scans/{scan_id}/cancel`.
