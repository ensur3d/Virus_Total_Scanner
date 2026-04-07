# VirusTotal Scanner

A desktop application built with PyQt6 that scans files using the VirusTotal API, monitors your Downloads folder for new files, and maintains a persistent scan history database.

## Features

- **Manual File Scan** — Select individual files or entire folders to scan against VirusTotal's 70+ antivirus engines
- **Auto-Scan Downloads** — Background monitoring of your Downloads folder; new files are automatically scanned as they appear
- **Scan History Database** — All scan results are cached in SQLite, avoiding redundant API calls and providing a full audit trail
- **Rate-Limited API** — Token bucket algorithm ensures compliance with the VirusTotal public API limit (4 requests/minute)
- **Secure API Key Storage** — API keys are stored using the system keyring, never in plain text
- **Modern GUI** — Clean, tabbed interface with animated progress indicators and color-coded results

## Project Structure

```
virus_total_scanner/
├── src/
│   ├── __init__.py           # Package init
│   ├── main.py               # Main application, all GUI widgets and logic
│   ├── vt_client.py          # VirusTotal API client with rate limiting and caching
│   ├── scan_history_db.py    # SQLite database for storing scan history
│   ├── api_key_manager.py    # API key storage using system keyring
│   └── download_monitor.py   # Background folder monitoring using watchdog
├── requirements.txt          # Python dependencies
├── QUICKSTART.md             # Quick start guide
└── README.md                 # This file
```

## Architecture

### Core Components

| Module | Purpose |
|---|---|
| `main.py` | Main window, tabbed interface, all GUI widgets (ManualScanWidget, AutoScanWidget, ScanHistoryWidget, ScanProgressWidget, ScanResultCard) |
| `vt_client.py` | VirusTotal API wrapper with token bucket rate limiting, scan caching, and async-to-sync bridge |
| `scan_history_db.py` | SQLite database layer for persistent scan record storage and retrieval |
| `api_key_manager.py` | Secure API key management via the system keyring |
| `download_monitor.py` | File system watcher using watchdog to detect new files in the Downloads folder |

### Data Flow

```
User Action (click/file detected)
    │
    ▼
ScanWorker (QThread) ──► RateLimitedClient ──► VirusTotal API
    │                        │
    │                        ▼
    │                   ScanHistoryDB (cache check / store)
    │                        │
    ▼                        ▼
ScanResult ──────────► GUI Update (main thread)
```


## Rate Limiting

The VirusTotal public API allows **4 requests per minute**. This application uses a **token bucket algorithm**:

- The bucket starts full with 4 tokens
- Each scan consumes 1 token
- Tokens refill continuously at a rate of 4 per minute (1 every 15 seconds)
- If no tokens are available, the thread waits until one is available
- The lock is released during `time.sleep()` to avoid blocking other threads

This ensures:
- First 4 scans proceed immediately
- Subsequent scans wait ~15 seconds each
- Unlimited scans over time without hitting API rate limits

## Database

SQLite database stored at `~/.config/virus_total_scanner/scan_history.db`:

- Scans are cached by `file_hash` — if the same file is scanned again, the cached result is returned instantly without consuming an API request. --SHA-256(Hash)

## Installation

### Prerequisites

- Python 3.9+
- A free VirusTotal API key (get one at [virustotal.com](https://www.virustotal.com/gui/join-us))

### System Dependencies (Debian/Ubuntu)

```bash
sudo apt install python3-pip python3-venv libxcb-cursor0 libxkbcommon0 libgl1
```

### Install

```bash
cd virus_total_scanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Starting the Application

```bash
cd virus_total_scanner
source venv/bin/activate
QT_QPA_PLATFORM=xcb python3 src/main.py
```

### First Run

1. On first launch, you'll be prompted to enter your VirusTotal API key
2. Check "Remember API key in system keyring" to save it securely
3. Click "OK" to start scanning

### Tabs

#### Manual Scan
- **Select File** — Browse for a single file and scan it
- **Scan Folder** — Select a folder to scan all files within it
- **Force Rescan** — Bypass the cache and re-upload to VirusTotal
- **Scan Results** — Detailed result cards showing file name, hash, and detection stats

#### Auto-Scan Downloads
- **Watch Downloads** — Toggle monitoring of your Downloads folder
- **Downloads Path** — Customize the folder path to monitor (default: `~/Downloads`)
- **Start/Stop** — Control the background monitor
- **Recent Scans** — Scrollable result cards for each detected file, identical to Manual Scan

#### Scan History
- Full table of all past scans loaded from the SQLite database
- Columns: Time, File, Hash, Size, Malicious, Suspicious, Undetected, Status
- File and Hash columns expand to fill available window space
- Hover over truncated cells to see the full value in a tooltip
- **Refresh** — Reload from database
- **Clear All** — Delete all history

#### Settings
- View and manage your stored API key
- Save, update, or remove the stored key
- Link to get a new API key from VirusTotal

## Scan Status Values

| Status | Color | Meaning |
|---|---|---|
| `pending` | Orange | Scan is queued |
| `in_progress` | Blue | Currently uploading/scanning |
| `completed` | Green | Scan finished, no threats detected |
| `completed` (malicious) | Red | Threats detected |
| `cached` | Teal | Result loaded from local database |
| `error` | Red | Scan failed (API error, network issue, etc.) |
| `not_found` | Gray | File not found in VirusTotal database |

## Configuration

The application stores data in:
- **Database**: `~/.config/virus_total_scanner/scan_history.db`
- **API Key**: System keyring (managed by the `keyring` library)

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `PyQt6` | >= 6.5.0 | Desktop GUI framework |
| `vt-py` | >= 0.22.0 | Official VirusTotal Python client |
| `keyring` | >= 23.0.0 | Secure credential storage |
| `watchdog` | >= 3.0.0 | File system event monitoring |

## Known Issues

### Wayland/X11 Compatibility

If you get Qt platform plugin errors, try:

```bash
QT_QPA_PLATFORM=wayland python3 src/main.py  # For Wayland
# or
QT_QPA_PLATFORM=xcb python3 src/main.py      # For X11
```

### API Rate Limits

The application respects VirusTotal's public API limits:
- 4 requests per minute
- 500 requests per day
- Scans may queue if you hit the limit

## License

This project is provided as-is for personal use.
This project is open source and available under the MIT License.
