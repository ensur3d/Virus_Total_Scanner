# Virus Total Scanner - Quick Start Guide


**Install dependencies:**

```bash
cd /home/minty/code_test/virus_total_scanner
python3 -m venv venv
source venv/bin/activate
pip install pyqt6 vt-py keyring watchdog
```

## Running the Application

```bash
cd /home/minty/code_test/virus_total_scanner
source venv/bin/activate
python3 src/main.py
```

### If you get display errors (Wayland/X11 issues):

```bash
# For X11 (most common on Linux)
QT_QPA_PLATFORM=xcb python3 src/main.py

# For Wayland
QT_QPA_PLATFORM=wayland python3 src/main.py
```

## Features

### 1. **Manual Scan Tab**
- Browse and select files to scan
- View real-time scan results

### 2. **Auto-Scan Downloads Tab**
- Monitor your Downloads folder for new files
- Automatic scanning when files are downloaded
- Real-time status updates

### 3. **Results Viewer Tab**
- Look up files by hash (SHA-256, SHA-1, MD5)
- View detailed VirusTotal analysis

### 4. **Scan History Tab**
- Complete history of all scanned files
- Shows status and detection counts

### 5. **Settings Tab (⚙)**
- **API Key Management** - View, change, or remove your API key
- Click the **eye icon (👁)** to show/hide the API key
- Stores key securely in system keyring

## API Key

You need a free VirusTotal API key from:
https://www.virustotal.com/gui/join-us

The key is stored securely using your system's keyring (not in plain text).

## Troubleshooting

### "Failed to create wl_display"
Run with XCB platform: `QT_QPA_PLATFORM=xcb python3 src/main.py`

### Scans not working
Check API key is set in Settings tab (bottom right status bar should show green checkmark)

### Rate limits
The app respects VirusTotal's limits (4 requests/minute, 500/day). Scans may queue if you hit limits.
