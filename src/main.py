import sys
import os
import time
import hashlib
import threading
from datetime import datetime
from typing import Dict, Any, Optional, List
from PyQt6.QtCore import Qt

def _setup_qt_platform():
    if "QT_QPA_PLATFORM" not in os.environ:
        os.environ["QT_QPA_PLATFORM"] = "xcb;wayland;linuxfb"
    os.environ.setdefault("QT_WAYLAND_DISABLE_WINDOWDECORATION", "1")

_setup_qt_platform()

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QPushButton, QLabel, QLineEdit, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar,
    QFileDialog, QMessageBox, QDialog, QDialogButtonBox,
    QStatusBar, QGroupBox, QCheckBox, QScrollArea, QFrame,
    QGridLayout, QSizePolicy, QSpacerItem, QToolButton
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
from PyQt6.QtGui import QFont, QColor, QPalette, QIcon, QAction, QPainter, QPixmap, QPen, QBrush

from api_key_manager import ApiKeyManager
from vt_client import RateLimitedClient, ScanResult, ScanStatus
from download_monitor import DownloadMonitor
from scan_history_db import ScanHistoryDB, ScanRecord


STYLESHEET = """
QMainWindow { background-color: #1e1e1e; }
QWidget { color: #e0e0e0; background-color: #1e1e1e; font-family: 'Segoe UI', sans-serif; font-size: 13px; }
QTabWidget::pane { border: 1px solid #3c3c3c; background-color: #252526; }
QTabBar::tab { background-color: #2d2d30; color: #cccccc; padding: 10px 20px; margin-right: 2px; border-top-left-radius: 4px; border-top-right-radius: 4px; }
QTabBar::tab:selected { background-color: #007acc; color: #ffffff; }
QPushButton { background-color: #0e639c; color: #ffffff; border: none; padding: 8px 16px; border-radius: 4px; min-width: 80px; }
QPushButton:hover { background-color: #1177bb; }
QPushButton:disabled { background-color: #3c3c3c; color: #808080; }
QPushButton#dangerButton { background-color: #c42b1c; }
QPushButton#dangerButton:hover { background-color: #d43f3a; }
QLineEdit { background-color: #3c3c3c; color: #e0e0e0; border: 1px solid #555555; border-radius: 4px; padding: 6px; }
QLineEdit:focus { border: 1px solid #007acc; }
QTextEdit { background-color: #1e1e1e; color: #e0e0e0; border: 1px solid #3c3c3c; border-radius: 4px; }
QTableWidget { background-color: #252526; alternate-background-color: #2d2d30; gridline-color: #3c3c3c; border: 1px solid #3c3c3c; }
QHeaderView::section { background-color: #2d2d30; color: #cccccc; padding: 6px; border: 1px solid #3c3c3c; }
QProgressBar { border: 1px solid #3c3c3c; border-radius: 4px; background-color: #3c3c3c; text-align: center; }
QProgressBar::chunk { background-color: #007acc; border-radius: 3px; }
QGroupBox { border: 1px solid #3c3c3c; border-radius: 4px; margin-top: 10px; padding-top: 10px; font-weight: bold; }
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
QFrame#resultCard { background-color: #2d2d30; border: 1px solid #3c3c3c; border-radius: 6px; padding: 10px; }
QToolButton { border: none; background-color: transparent; padding: 4px; }
QToolButton:hover { background-color: #3c3c3c; border-radius: 4px; }
"""


class ScanWorker(QThread):
    progress = pyqtSignal(str, str)
    finished = pyqtSignal(ScanResult)
    
    def __init__(self, client: RateLimitedClient, file_path: str, force_rescan: bool = False, parent=None):
        super().__init__(parent)
        self.client = client
        self.file_path = file_path
        self.force_rescan = force_rescan
    
    def run(self):
        result = self.client.scan_file(
            self.file_path,
            progress_callback=self._on_progress,
            force_rescan=self.force_rescan
        )
        self.finished.emit(result)
    
    def _on_progress(self, status: ScanStatus, message: str):
        self.progress.emit(status.value, message)





class ApiKeyDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("API Key Management")
        self.setModal(True)
        self.setMinimumWidth(550)
        
        layout = QVBoxLayout()
        
        # Title with icon
        title_layout = QHBoxLayout()
        title_label = QLabel("🔑 API Key Management")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #007acc;")
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        layout.addLayout(title_layout)
        
        # Current API key info
        info_text = "Your API key is stored securely using the system keyring."
        info_label = QLabel(info_text)
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        layout.addWidget(QLabel(""))  # Spacer
        
        # API Key input with eye toggle
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("API Key:"))
        
        self.api_key_input = QLineEdit()
        self.api_key_input.setPlaceholderText("Enter your VirusTotal API key...")
        self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        key_layout.addWidget(self.api_key_input, 1)
        
        # Eye toggle button
        self.eye_btn = QToolButton()
        self.eye_btn.setText("👁")
        self.eye_btn.setStyleSheet("font-size: 14px;")
        self.eye_btn.setCheckable(True)
        self.eye_btn.toggled.connect(self._toggle_key_visibility)
        key_layout.addWidget(self.eye_btn)
        
        layout.addLayout(key_layout)
        
        # API key link
        link_layout = QHBoxLayout()
        link_layout.addStretch()
        link_label = QLabel('<a href="https://www.virustotal.com/gui/join-us" style="color: #007acc;">Get API Key</a>')
        link_label.setOpenExternalLinks(True)
        link_layout.addWidget(link_label)
        link_layout.addStretch()
        layout.addLayout(link_layout)
        
        layout.addWidget(QLabel(""))  # Spacer
        
        # Options
        self.remember_checkbox = QCheckBox("Remember API key in system keyring")
        self.remember_checkbox.setChecked(True)
        layout.addWidget(self.remember_checkbox)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #4caf50;")
        layout.addWidget(self.status_label)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.setLayout(layout)
        
        # Load existing key if any
        existing_key = ApiKeyManager.get_api_key()
        if existing_key:
            self.api_key_input.setText(existing_key)
            self.status_label.setText("Current API key is stored")
    
    def _toggle_key_visibility(self, checked: bool):
        if checked:
            self.api_key_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.eye_btn.setText("👁️‍🗨️")
        else:
            self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.eye_btn.setText("👁")
    
    def get_api_key(self) -> str:
        return self.api_key_input.text().strip()
    
    def should_remember(self) -> bool:
        return self.remember_checkbox.isChecked()


class ScanResultCard(QFrame):
    def __init__(self, result: ScanResult, parent=None):
        super().__init__(parent)
        self.result_data = result
        self.file_path = result.file_path if result.file_path else ""
        self.setObjectName("resultCard")
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        
        layout = QVBoxLayout()
        
        header_layout = QHBoxLayout()
        
        file_name = os.path.basename(result.file_path) if result.file_path else result.file_hash[:16] + "..."
        self.filename_label = QLabel(f"<b>{file_name}</b>")
        self.filename_label.setStyleSheet("font-size: 14px;")
        header_layout.addWidget(self.filename_label)
        
        header_layout.addStretch()
        
        self.status_label = QLabel()
        self.status_label.setObjectName("statusLabel")
        header_layout.addWidget(self.status_label)
        
        layout.addLayout(header_layout)
        
        if result.file_hash:
            hash_label = QLabel(f"Hash: {result.file_hash}")
            hash_label.setStyleSheet("color: #888888; font-size: 11px;")
            layout.addWidget(hash_label)
        
        if result.error:
            error_label = QLabel(f"Error: {result.error}")
            error_label.setStyleSheet("color: #f44336;")
            layout.addWidget(error_label)
        elif result.data:
            self._add_result_details(layout, result)
        
        self.setLayout(layout)
        self._update_status()
    
    def _add_result_details(self, layout: QVBoxLayout, result: ScanResult):
        if "stats" in result.data:
            stats = result.data["stats"]
            if stats:
                stats_text = " | ".join([f"{k}: {v}" for k, v in stats.items() if v is not None])
                stats_label = QLabel(f"Stats: {stats_text}")
                stats_label.setStyleSheet("color: #4ec9b0;")
                layout.addWidget(stats_label)
        
        if "last_analysis_stats" in result.data:
            last_stats = result.data["last_analysis_stats"]
            if last_stats:
                mal_count = last_stats.get("malicious", 0)
                susp_count = last_stats.get("suspicious", 0)
                und_count = last_stats.get("undetected", 0)
                
                stats_summary = f"Malicious: {mal_count} | Suspicious: {susp_count} | Undetected: {und_count}"
                stats_label = QLabel(stats_summary)
                layout.addWidget(stats_label)
                
                if mal_count > 0 or susp_count > 0:
                    stats_label.setStyleSheet("color: #f44336;")
                else:
                    stats_label.setStyleSheet("color: #4caf50;")
    
    def _update_status(self):
        status_colors = {
            ScanStatus.PENDING: "#ff9800",
            ScanStatus.IN_PROGRESS: "#2196f3",
            ScanStatus.COMPLETED: "#4caf50",
            ScanStatus.ERROR: "#f44336",
            ScanStatus.NOT_FOUND: "#9e9e9e",
            ScanStatus.CACHED: "#4ec9b0"
        }
        
        color = status_colors.get(self.result_data.status, "#9e9e9e")
        status_text = self.result_data.status.value.upper()
        if self.result_data.from_cache:
            status_text += " (CACHED)"
        
        self.status_label.setText(f"<span style='color: {color}'>{status_text}</span>")
        
        if self.result_data.status == ScanStatus.COMPLETED:
            self.status_label.setStyleSheet(f"color: {color}; font-weight: bold;")
        else:
            self.status_label.setStyleSheet(f"color: {color};")


class ScanProgressWidget(QWidget):
    """Simple scan progress widget with spinning wheel."""
    
    # Signal to safely start/stop timer from any thread
    _timer_control_signal = pyqtSignal(bool)
    # Signal to safely update status text from any thread
    _status_update_signal = pyqtSignal(str)
    # Signal to safely update status style from any thread
    _style_update_signal = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.progress_wheel = None
        self.status_label = None
        
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Progress wheel and status (horizontal layout)
        row_layout = QHBoxLayout()
        
        # Animated progress wheel (spinning circle)
        self.progress_wheel = QLabel()
        self.progress_wheel.setFixedSize(24, 24)
        self._set_wheel_pixmap(False)  # Start not spinning
        row_layout.addWidget(self.progress_wheel)
        
        self.status_label = QLabel("Initializing scan...")
        self.status_label.setStyleSheet("font-weight: bold;")
        row_layout.addWidget(self.status_label)
        
        row_layout.addStretch()
        
        layout.addLayout(row_layout)
        self.setLayout(layout)
        
        # Animation timer
        self.animation_angle = 0
        self.animation_timer = QTimer()
        self.animation_timer.timeout.connect(self._rotate_wheel)
        
        # Connect the signals to the slots
        self._timer_control_signal.connect(self._on_timer_control)
        self._status_update_signal.connect(self._on_status_update)
        self._style_update_signal.connect(self._on_style_update)
    
    def _set_wheel_pixmap(self, spinning: bool):
        """Create a simple spinning wheel pixmap."""
        if spinning:
            self.progress_wheel.setPixmap(self._create_spinning_pixmap(self.animation_angle))
        else:
            self.progress_wheel.setPixmap(self._create_spinning_pixmap(0))
    
    def _create_spinning_pixmap(self, angle: int):
        """Create a circular progress indicator."""
        size = 24
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.GlobalColor.transparent)
        
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Draw circle
        painter.setPen(QPen(QColor("#007acc"), 2))
        painter.drawEllipse(2, 2, size-4, size-4)
        
        # Draw arc based on angle
        painter.setPen(QPen(QColor("#007acc"), 3))
        start_angle = angle * 16  # Qt uses 1/16th degree units
        span_angle = 90 * 16
        painter.drawArc(2, 2, size-4, size-4, start_angle, span_angle)
        
        painter.end()
        return pixmap
    
    def _rotate_wheel(self):
        """Rotate the progress wheel."""
        self.animation_angle = (self.animation_angle + 15) % 360
        self._set_wheel_pixmap(True)
    
    def set_scanning(self, is_scanning: bool):
        """Set whether we're actively scanning."""
        if is_scanning:
            self._status_update_signal.emit("Scanning file...")
            self._timer_control_signal.emit(True)
        else:
            self._timer_control_signal.emit(False)
            self._set_wheel_pixmap(False)
    
    def _on_timer_control(self, start: bool):
        """Handle timer start/stop requests from any thread."""
        if start:
            self.animation_timer.start(50)
        else:
            self.animation_timer.stop()
    
    def _on_status_update(self, text: str):
        """Handle status text updates from any thread."""
        self.status_label.setText(text)
    
    def _on_style_update(self, style: str):
        """Handle style updates from any thread."""
        self.status_label.setStyleSheet(style)


class ManualScanWidget(QWidget):
    def __init__(self, vt_client: RateLimitedClient, history_widget, parent=None):
        super().__init__(parent)
        self.vt_client = vt_client
        self.history_widget = history_widget
        self.workers: List[ScanWorker] = []
        self._folder_total_files = 0
        self._folder_completed_count = 0
        self._scan_in_progress = False
        
        layout = QVBoxLayout()
        
        group = QGroupBox("Select File to Scan")
        group_layout = QVBoxLayout()


class ManualScanWidget(QWidget):
    def __init__(self, vt_client: RateLimitedClient, history_widget, parent=None):
        super().__init__(parent)
        self.vt_client = vt_client
        self.history_widget = history_widget
        self.workers: List[ScanWorker] = []
        
        layout = QVBoxLayout()
        
        group = QGroupBox("Select File to Scan")
        group_layout = QVBoxLayout()
        
        file_select_layout = QHBoxLayout()
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("Select a file...")
        self.file_path_input.setReadOnly(True)
        file_select_layout.addWidget(self.file_path_input)
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_file)
        file_select_layout.addWidget(browse_btn)
        
        group_layout.addLayout(file_select_layout)
        
        options_layout = QHBoxLayout()
        self.force_rescan_checkbox = QCheckBox("Force rescan (ignore cache)")
        options_layout.addWidget(self.force_rescan_checkbox)
        options_layout.addStretch()
        group_layout.addLayout(options_layout)
        
        btn_layout = QHBoxLayout()
        self.scan_btn = QPushButton("Scan File")
        self.scan_btn.clicked.connect(self._start_scan)
        self.scan_btn.setEnabled(False)
        btn_layout.addWidget(self.scan_btn)
        
        self.rescan_btn = QPushButton("Rescan (Bypass Cache)")
        self.rescan_btn.clicked.connect(self._start_rescan)
        self.rescan_btn.setEnabled(False)
        btn_layout.addWidget(self.rescan_btn)
        
        group_layout.addLayout(btn_layout)
        
        group.setLayout(group_layout)
        layout.addWidget(group)
        
        # Folder scan section
        folder_group = QGroupBox("Scan Folder")
        folder_group_layout = QVBoxLayout()
        
        folder_select_layout = QHBoxLayout()
        self.folder_path_input = QLineEdit()
        self.folder_path_input.setPlaceholderText("Select a folder...")
        self.folder_path_input.setReadOnly(True)
        folder_select_layout.addWidget(self.folder_path_input)
        
        folder_browse_btn = QPushButton("Browse...")
        folder_browse_btn.clicked.connect(self._browse_folder)
        folder_select_layout.addWidget(folder_browse_btn)
        
        folder_group_layout.addLayout(folder_select_layout)
        
        folder_options_layout = QHBoxLayout()
        self.folder_force_rescan_checkbox = QCheckBox("Force rescan (ignore cache)")
        folder_options_layout.addWidget(self.folder_force_rescan_checkbox)
        folder_options_layout.addStretch()
        folder_group_layout.addLayout(folder_options_layout)
        
        folder_btn_layout = QHBoxLayout()
        self.scan_folder_btn = QPushButton("Scan Folder")
        self.scan_folder_btn.clicked.connect(self._start_folder_scan)
        self.scan_folder_btn.setEnabled(False)
        folder_btn_layout.addWidget(self.scan_folder_btn)
        
        self.rescan_folder_btn = QPushButton("Rescan Folder")
        self.rescan_folder_btn.clicked.connect(self._start_folder_rescan)
        self.rescan_folder_btn.setEnabled(False)
        folder_btn_layout.addWidget(self.rescan_folder_btn)
        
        folder_group_layout.addLayout(folder_btn_layout)
        
        # Show status of folder scan
        self.folder_status_label = QLabel("")
        folder_group_layout.addWidget(self.folder_status_label)
        
        folder_group.setLayout(folder_group_layout)
        layout.addWidget(folder_group)
        
        # Progress widget (will be shown during scan)
        self.progress_widget = ScanProgressWidget()
        self.progress_widget.setVisible(False)
        layout.addWidget(self.progress_widget)
        
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout()
        
        self.results_container = QVBoxLayout()
        self.results_container.setAlignment(Qt.AlignmentFlag.AlignTop)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        results_widget = QWidget()
        results_widget.setLayout(self.results_container)
        scroll.setWidget(results_widget)
        
        results_layout.addWidget(scroll)
        results_group.setLayout(results_layout)
        
        layout.addWidget(results_group, 1)
        
        self.setLayout(layout)
    
    def _browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Scan", os.path.expanduser("~/Downloads"), "All Files (*.*)")
        if file_path:
            self.file_path_input.setText(file_path)
            self.scan_btn.setEnabled(True)
            self.rescan_btn.setEnabled(True)
    
    def _start_scan(self):
        self._start_scan_impl(force_rescan=False)
    
    def _start_rescan(self):
        self._start_scan_impl(force_rescan=True)
    
    def _start_scan_impl(self, force_rescan: bool):
        file_path = self.file_path_input.text()
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Error", "Please select a valid file.")
            return
        
        self.scan_btn.setEnabled(False)
        self.rescan_btn.setEnabled(False)
        
        # Show progress widget
        self.progress_widget.setVisible(True)
        self.progress_widget.set_scanning(True)
        self._scan_in_progress = True
        
        worker = ScanWorker(self.vt_client, file_path, force_rescan)
        worker.progress.connect(self._on_progress)
        worker.finished.connect(self._on_finished)
        worker.finished.connect(worker.deleteLater)
        self.workers.append(worker)
        worker.start()
    
    def _on_progress(self, status: str, message: str):
        # Use signal to update status text from worker thread
        self.progress_widget._status_update_signal.emit(f"[{status.upper()}] {message}")
        
        if status == "completed":
            self.progress_widget.set_scanning(False)
        elif status == "error":
            # Use signal to update style from worker thread
            self.progress_widget._style_update_signal.emit("color: #f44336;")
            self.progress_widget.set_scanning(False)
        elif status == "cached":
            # Use signal to update style from worker thread
            self.progress_widget._style_update_signal.emit("color: #4ec9b0;")
            self.progress_widget.set_scanning(False)
    
    def _on_finished(self, result: ScanResult):
        self.scan_btn.setEnabled(True)
        self.rescan_btn.setEnabled(True)
        
        # Reset scan in progress flag
        self._scan_in_progress = False
        
        # Hide progress widget after a short delay ONLY if no other scan is in progress
        def hide_if_not_scanning():
            if not self._scan_in_progress:
                self.progress_widget.setVisible(False)
        
        QTimer.singleShot(2000, hide_if_not_scanning)
        
        card = ScanResultCard(result)
        self.results_container.insertWidget(0, card)
        if self.history_widget:
            self.history_widget.add_result(result)
    
    def _browse_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Select Folder to Scan", os.path.expanduser("~"))
        if folder_path:
            self.folder_path_input.setText(folder_path)
            self.scan_folder_btn.setEnabled(True)
            self.rescan_folder_btn.setEnabled(True)
    
    def _start_folder_scan(self):
        self._start_folder_scan_impl(force_rescan=False)
    
    def _start_folder_rescan(self):
        self._start_folder_scan_impl(force_rescan=True)
    
    def _start_folder_scan_impl(self, force_rescan: bool):
        folder_path = self.folder_path_input.text()
        if not folder_path or not os.path.isdir(folder_path):
            QMessageBox.warning(self, "Error", "Please select a valid folder.")
            return
        
        # Find all files in the folder
        files_to_scan = []
        for root, dirs, files in os.walk(folder_path):
            for filename in files:
                if not filename.startswith("."):  # Skip hidden files
                    files_to_scan.append(os.path.join(root, filename))
        
        if not files_to_scan:
            self.folder_status_label.setText("No files found in folder")
            self.folder_status_label.setStyleSheet("color: #ff9800;")
            return
        
        # Update status
        self.scan_folder_btn.setEnabled(False)
        self.rescan_folder_btn.setEnabled(False)
        self.folder_status_label.setText(f"Scanning {len(files_to_scan)} files...")
        self.folder_status_label.setStyleSheet("color: #007acc;")
        
        # Show progress widget
        self.progress_widget.setVisible(True)
        self.progress_widget.set_scanning(True)
        self._scan_in_progress = True
        
        # Track total files and completed count
        self._folder_total_files = len(files_to_scan)
        self._folder_completed_count = 0
        
        # Scan each file
        for file_path in files_to_scan:
            worker = ScanWorker(self.vt_client, file_path, force_rescan)
            worker.progress.connect(self._on_progress)
            worker.finished.connect(self._on_folder_scan_finished)
            worker.finished.connect(lambda r, w=worker: self._cleanup_worker(w))
            self.workers.append(worker)
            worker.start()
    
    def _cleanup_worker(self, worker: ScanWorker):
        """Remove worker from list when finished."""
        if worker in self.workers:
            self.workers.remove(worker)
    
    def _on_folder_scan_finished(self, result: ScanResult):
        # Add result to history/database
        if self.history_widget:
            self.history_widget.add_result(result)
        
        # Add result card to scan results section (same as single file scan)
        card = ScanResultCard(result)
        self.results_container.insertWidget(0, card)
        
        # Update completed count
        self._folder_completed_count += 1
        
        # Update status label with progress
        self.folder_status_label.setText(
            f"Scanning... {self._folder_completed_count}/{self._folder_total_files} files"
        )
        
        # Re-enable buttons when all scans are done
        if self._folder_completed_count >= self._folder_total_files:
            self.scan_folder_btn.setEnabled(True)
            self.rescan_folder_btn.setEnabled(True)
            self.folder_status_label.setText("Folder scan complete")
            self.folder_status_label.setStyleSheet("color: #4caf50;")
            self._scan_in_progress = False
            # Hide progress widget after delay only if no other scan is in progress
            def hide_if_not_scanning():
                if not self._scan_in_progress:
                    self.progress_widget.setVisible(False)
            QTimer.singleShot(2000, hide_if_not_scanning)


class AutoScanWidget(QWidget):
    scan_requested = pyqtSignal(str)
    file_detected = pyqtSignal(str)
    
    def __init__(self, vt_client: RateLimitedClient, history_widget, parent=None):
        super().__init__(parent)
        self.vt_client = vt_client
        self.history_widget = history_widget
        self.monitor: Optional[DownloadMonitor] = None
        self.workers: List[ScanWorker] = []
        self._scan_in_progress = False
        
        # Connect signal to marshal file detection to main thread
        self.file_detected.connect(self._handle_new_file, Qt.ConnectionType.QueuedConnection)
        
        layout = QVBoxLayout()
        
        controls_group = QGroupBox("Download Monitor Controls")
        controls_layout = QVBoxLayout()
        
        self.watch_checkbox = QCheckBox("Watch Downloads folder for new files")
        self.watch_checkbox.setChecked(False)
        controls_layout.addWidget(self.watch_checkbox)
        
        download_path_layout = QHBoxLayout()
        download_path_layout.addWidget(QLabel("Downloads Path:"))
        self.download_path_input = QLineEdit(os.path.expanduser("~/Downloads"))
        download_path_layout.addWidget(self.download_path_input)
        controls_layout.addLayout(download_path_layout)
        
        buttons_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Monitoring")
        self.start_btn.clicked.connect(self._start_monitoring)
        buttons_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("Stop Monitoring")
        self.stop_btn.clicked.connect(self._stop_monitoring)
        self.stop_btn.setEnabled(False)
        buttons_layout.addWidget(self.stop_btn)
        
        controls_layout.addLayout(buttons_layout)
        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)
        
        # Progress widget (will be shown during scan)
        self.progress_widget = ScanProgressWidget()
        self.progress_widget.setVisible(False)
        layout.addWidget(self.progress_widget)
        
        detected_group = QGroupBox("Recent Scans")
        detected_layout = QVBoxLayout()
        
        # Recent scans container (like Manual Scan results section)
        self.recent_scans_container = QVBoxLayout()
        self.recent_scans_container.setAlignment(Qt.AlignmentFlag.AlignTop)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        recent_scans_widget = QWidget()
        recent_scans_widget.setLayout(self.recent_scans_container)
        scroll.setWidget(recent_scans_widget)
        
        detected_layout.addWidget(scroll)
        
        detected_group.setLayout(detected_layout)
        layout.addWidget(detected_group, 1)
        
        self.setLayout(layout)
    
    def _start_monitoring(self):
        download_path = self.download_path_input.text().strip()
        if not download_path:
            QMessageBox.warning(self, "Error", "Please enter a valid downloads path.")
            return
        
        self.monitor = DownloadMonitor(download_path, self._on_new_file)
        if self.monitor.start():
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.watch_checkbox.setChecked(True)
            self.download_path_input.setEnabled(False)
    
    def _stop_monitoring(self):
        if self.monitor:
            self.monitor.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.watch_checkbox.setChecked(False)
        self.download_path_input.setEnabled(True)
    
    def _on_new_file(self, file_path: str):
        # Emit signal to marshal to main thread (queued connection)
        self.file_detected.emit(file_path)
    
    def _handle_new_file(self, file_path: str):
        # This runs on the main thread
        self.progress_widget.setVisible(True)
        self.progress_widget.set_scanning(True)
        self._scan_in_progress = True
        
        # Add result card to recent scans
        placeholder_result = ScanResult(
            file_path=file_path,
            file_hash="",
            status=ScanStatus.PENDING,
            data={}
        )
        card = ScanResultCard(placeholder_result)
        card.file_path = file_path
        self.recent_scans_container.insertWidget(0, card)
        
        worker = ScanWorker(self.vt_client, file_path)
        worker.progress.connect(self._on_progress)
        worker.finished.connect(self._on_scan_finished)
        worker.finished.connect(lambda r, w=worker: self._cleanup_worker(w))
        worker.finished.connect(worker.deleteLater)
        self.workers.append(worker)
        worker.start()
    
    def _on_progress(self, status: str, message: str):
        # Use signal to update status text from worker thread
        self.progress_widget._status_update_signal.emit(f"[{status.upper()}] {message}")
        
        if status == "completed":
            self.progress_widget.set_scanning(False)
        elif status == "error":
            # Use signal to update style from worker thread
            self.progress_widget._style_update_signal.emit("color: #f44336;")
            self.progress_widget.set_scanning(False)
        elif status == "cached":
            # Use signal to update style from worker thread
            self.progress_widget._style_update_signal.emit("color: #4ec9b0;")
            self.progress_widget.set_scanning(False)
    
    def _cleanup_worker(self, worker: ScanWorker):
        """Remove worker from list when finished."""
        if worker in self.workers:
            self.workers.remove(worker)
        
        # Check if all scans are finished
        if len(self.workers) == 0:
            self._scan_in_progress = False
            # Hide progress widget after a short delay only if no other scan is in progress
            def hide_if_not_scanning():
                if not self._scan_in_progress:
                    self.progress_widget.setVisible(False)
            QTimer.singleShot(2000, hide_if_not_scanning)
    
    def _on_scan_finished(self, result: ScanResult):
        # Use QTimer.singleShot to ensure GUI updates happen in main thread
        def update_gui():
            # Update recent scans container (find the card for this file and update it)
            # Since we inserted cards at position 0, we need to search through the container
            for i in range(self.recent_scans_container.count()):
                item = self.recent_scans_container.itemAt(i)
                if item and item.widget():
                    card = item.widget()
                    if hasattr(card, 'file_path'):
                        if card.file_path == result.file_path:
                            # Update this card with the actual result
                            # Remove the old card and insert new one at the same position
                            self.recent_scans_container.removeWidget(card)
                            card.deleteLater()
                            
                            # Create new card with actual result
                            new_card = ScanResultCard(result)
                            self.recent_scans_container.insertWidget(i, new_card)
                            break
        
        QTimer.singleShot(0, update_gui)
        
        if self.history_widget:
            self.history_widget.add_result(result)
    
    def closeEvent(self, event):
        if self.monitor and self.monitor.is_running():
            self.monitor.stop()
        super().closeEvent(event)





class ScanHistoryWidget(QWidget):
    def __init__(self, client: RateLimitedClient, parent=None):
        super().__init__(parent)
        self.client = client
        self.results: List[ScanRecord] = []
        
        layout = QVBoxLayout()
        
        group = QGroupBox("Scan History (From Database)")
        group_layout = QVBoxLayout()
        
        # Stats bar
        stats_layout = QHBoxLayout()
        self.stats_label = QLabel("Loading stats...")
        stats_layout.addWidget(self.stats_label)
        stats_layout.addStretch()
        group_layout.addLayout(stats_layout)
        
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels(["Time", "File", "Hash", "Size", "Malicious", "Suspicious", "Undetected", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 160)
        self.table.setColumnWidth(3, 80)
        self.table.setColumnWidth(4, 90)
        self.table.setColumnWidth(5, 100)
        self.table.setColumnWidth(6, 100)
        self.table.setColumnWidth(7, 100)
        group_layout.addWidget(self.table)
        
        btn_layout = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self._load_from_db)
        btn_layout.addWidget(self.refresh_btn)
        
        self.clear_btn = QPushButton("Clear All")
        self.clear_btn.setObjectName("dangerButton")
        self.clear_btn.clicked.connect(self._clear_all)
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addStretch()
        
        group_layout.addLayout(btn_layout)
        
        group.setLayout(group_layout)
        layout.addWidget(group)
        
        self.setLayout(layout)
        
        self._load_from_db()
    
    def add_result(self, result: ScanResult):
        """Add a result (from scan) to the history widget."""
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        time_str = datetime.fromtimestamp(result.timestamp).strftime("%H:%M:%S")
        self.table.setItem(row, 0, QTableWidgetItem(time_str))
        
        filename = os.path.basename(result.file_path) if result.file_path else result.file_hash[:16] + "..."
        file_item = QTableWidgetItem(filename)
        file_item.setToolTip(result.file_path if result.file_path else filename)
        self.table.setItem(row, 1, file_item)
        
        # Hash column - show full hash on hover
        hash_display = result.file_hash[:16] + "..." if len(result.file_hash) > 16 else result.file_hash
        hash_item = QTableWidgetItem(hash_display)
        hash_item.setToolTip(result.file_hash)
        self.table.setItem(row, 2, hash_item)
        
        # Size column
        size_text = ""
        if result.file_path and os.path.exists(result.file_path):
            size = os.path.getsize(result.file_path)
            if size < 1024:
                size_text = f"{size} B"
            elif size < 1024*1024:
                size_text = f"{size/1024:.1f} KB"
            else:
                size_text = f"{size/1024/1024:.1f} MB"
        self.table.setItem(row, 3, QTableWidgetItem(size_text))
        
        stats = result.data.get("last_analysis_stats", result.data.get("stats", {}))
        self.table.setItem(row, 4, QTableWidgetItem(str(stats.get("malicious", 0))))
        self.table.setItem(row, 5, QTableWidgetItem(str(stats.get("suspicious", 0))))
        self.table.setItem(row, 6, QTableWidgetItem(str(stats.get("undetected", 0))))
        
        status_item = QTableWidgetItem(result.status.value)
        if result.status == ScanStatus.COMPLETED:
            status_item.setForeground(QColor("#4caf50"))
        elif result.status == ScanStatus.ERROR:
            status_item.setForeground(QColor("#f44336"))
        elif result.status == ScanStatus.CACHED:
            status_item.setForeground(QColor("#4ec9b0"))
        self.table.setItem(row, 7, status_item)
    
    def _load_from_db(self):
        """Load history from database."""
        records = self.client.get_scan_history()
        self.table.setRowCount(0)
        
        for record in records:
            row = self.table.rowCount()
            self.table.insertRow(row)
            
            time_str = datetime.fromtimestamp(record.scan_timestamp).strftime("%Y-%m-%d %H:%M:%S")
            self.table.setItem(row, 0, QTableWidgetItem(time_str))
            
            self.table.setItem(row, 1, QTableWidgetItem(record.file_name or record.file_hash[:16] + "..."))
            
            # Hash column - show full hash on hover
            hash_display = record.file_hash[:16] + "..." if len(record.file_hash) > 16 else record.file_hash
            hash_item = QTableWidgetItem(hash_display)
            hash_item.setToolTip(record.file_hash)
            self.table.setItem(row, 2, hash_item)
            
            size_text = ""
            if record.file_size > 0:
                if record.file_size < 1024:
                    size_text = f"{record.file_size} B"
                elif record.file_size < 1024*1024:
                    size_text = f"{record.file_size/1024:.1f} KB"
                else:
                    size_text = f"{record.file_size/1024/1024:.1f} MB"
            self.table.setItem(row, 3, QTableWidgetItem(size_text))
            
            self.table.setItem(row, 4, QTableWidgetItem(str(record.malicious_count)))
            self.table.setItem(row, 5, QTableWidgetItem(str(record.suspicious_count)))
            self.table.setItem(row, 6, QTableWidgetItem(str(record.undetected_count)))
            
            status_item = QTableWidgetItem(record.scan_status)
            if record.scan_status == "completed":
                status_item.setForeground(QColor("#4caf50"))
                if record.malicious_count > 0:
                    status_item.setForeground(QColor("#f44336"))
            elif record.scan_status == "error":
                status_item.setForeground(QColor("#f44336"))
            elif record.scan_status == "cached":
                status_item.setForeground(QColor("#4ec9b0"))
            self.table.setItem(row, 7, status_item)
        
        # Update stats
        stats = self.client.db.get_stats()
        self.stats_label.setText(f"Total: {stats['total_scans']} | Completed: {stats['completed_scans']} | Malicious: {stats['malicious_files']}")
    
    def _clear_all(self):
        reply = QMessageBox.question(
            self, "Clear History",
            "Are you sure you want to clear all scan history?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.client.db.clear_all()
            self._load_from_db()


class ApiKeySettingsWidget(QWidget):
    # Signal must be defined at class level, not in __init__
    api_key_updated = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        layout = QVBoxLayout()
        
        group = QGroupBox("API Key Settings")
        group_layout = QVBoxLayout()
        
        # Info section
        info_label = QLabel(
            "Your API key is stored securely in the system keyring.\n"
            "You can view, change, or remove it here."
        )
        info_label.setWordWrap(True)
        group_layout.addWidget(info_label)
        
        group_layout.addWidget(QLabel(""))  # Spacer
        
        # Current API key display
        key_label_layout = QHBoxLayout()
        key_label_layout.addWidget(QLabel("Current API Key:"))
        key_label_layout.addStretch()
        group_layout.addLayout(key_label_layout)
        
        # API key input with eye toggle
        key_input_layout = QHBoxLayout()
        self.api_key_input = QLineEdit()
        self.api_key_input.setPlaceholderText("No API key stored")
        self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        key_input_layout.addWidget(self.api_key_input, 1)
        
        # Eye toggle button for show/hide
        self.eye_btn = QToolButton()
        self.eye_btn.setText("👁")
        self.eye_btn.setStyleSheet("font-size: 14px;")
        self.eye_btn.setCheckable(True)
        self.eye_btn.toggled.connect(self._toggle_key_visibility)
        key_input_layout.addWidget(self.eye_btn)
        
        group_layout.addLayout(key_input_layout)
        
        # Buttons
        buttons_layout = QHBoxLayout()
        
        save_btn = QPushButton("Save API Key")
        save_btn.clicked.connect(self._save_api_key)
        buttons_layout.addWidget(save_btn)
        
        remove_btn = QPushButton("Remove API Key")
        remove_btn.setObjectName("dangerButton")
        remove_btn.clicked.connect(self._remove_api_key)
        buttons_layout.addWidget(remove_btn)
        
        group_layout.addLayout(buttons_layout)
        
        # Status label
        self.status_label = QLabel("")
        group_layout.addWidget(self.status_label)
        
        # API key link
        link_layout = QHBoxLayout()
        link_layout.addStretch()
        link_label = QLabel('<a href="https://www.virustotal.com/gui/join-us" style="color: #007acc;">Get API Key</a>')
        link_label.setOpenExternalLinks(True)
        link_layout.addWidget(link_label)
        link_layout.addStretch()
        group_layout.addLayout(link_layout)
        
        group.setLayout(group_layout)
        layout.addWidget(group)
        
        layout.addStretch()
        
        self.setLayout(layout)
        
        self._load_api_key()
    
    def _load_api_key(self):
        existing_key = ApiKeyManager.get_api_key()
        if existing_key:
            self.api_key_input.setText(existing_key)
            self.status_label.setText("✓ API key is stored")
            self.status_label.setStyleSheet("color: #4caf50;")
        else:
            self.api_key_input.clear()
            self.status_label.setText("✗ No API key stored")
            self.status_label.setStyleSheet("color: #f44336;")
    
    def _toggle_key_visibility(self, checked: bool):
        if checked:
            self.api_key_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.eye_btn.setText("👁️‍🗨️")
        else:
            self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.eye_btn.setText("👁")
    
    def _save_api_key(self):
        api_key = self.api_key_input.text().strip()
        if not api_key:
            self.status_label.setText("⚠ API key cannot be empty")
            self.status_label.setStyleSheet("color: #ff9800;")
            return
        
        try:
            ApiKeyManager.save_api_key(api_key)
            self.status_label.setText("✓ API key saved successfully")
            self.status_label.setStyleSheet("color: #4caf50;")
            self.api_key_updated.emit()
        except Exception as e:
            self.status_label.setText(f"✗ Error saving API key: {e}")
            self.status_label.setStyleSheet("color: #f44336;")
    
    def _remove_api_key(self):
        reply = QMessageBox.question(
            self, "Remove API Key",
            "Are you sure you want to remove the API key?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                ApiKeyManager.delete_api_key()
                self.api_key_input.clear()
                self.status_label.setText("✗ API key removed")
                self.status_label.setStyleSheet("color: #f44336;")
                self.api_key_updated.emit()
            except Exception as e:
                self.status_label.setText(f"✗ Error removing API key: {e}")
                self.status_label.setStyleSheet("color: #f44336;")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.vt_client: Optional[RateLimitedClient] = None
        self.api_key_status_label: Optional[QLabel] = None
        self.setWindowTitle("Virus Total Scanner")
        self.setMinimumSize(1000, 700)
        self._init_ui()
        self._check_api_key()
    
    def _init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        
        self.tabs = QTabWidget()
        
        self.manual_scan_tab = QWidget()
        self.auto_scan_tab = QWidget()
        self.history_tab = QWidget()
        self.settings_tab = QWidget()
        
        self.tabs.addTab(self.manual_scan_tab, "Manual Scan")
        self.tabs.addTab(self.auto_scan_tab, "Auto-Scan Downloads")
        self.tabs.addTab(self.history_tab, "Scan History")
        self.tabs.addTab(self.settings_tab, "⚙ Settings")
        
        layout.addWidget(self.tabs)
        central_widget.setLayout(layout)
        
        # API Key status bar
        self.api_key_status_label = QLabel("API Key: Not set")
        self.api_key_status_label.setStyleSheet("color: #ff9800;")
        self.statusBar().addPermanentWidget(self.api_key_status_label)
        self.statusBar().showMessage("Ready")
        
        menu_bar = self.menuBar()
        settings_menu = menu_bar.addMenu("Settings")
        
        api_key_action = QAction("Manage API Key", self)
        api_key_action.triggered.connect(self._show_api_key_dialog)
        settings_menu.addAction(api_key_action)
        settings_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        settings_menu.addAction(exit_action)
    
    def _check_api_key(self):
        if ApiKeyManager.has_api_key():
            self._update_api_key_status(True)
            self._initialize_client()
        else:
            self._show_api_key_dialog()
    
    def _update_api_key_status(self, has_key: bool):
        if has_key:
            self.api_key_status_label.setText("API Key: ✓ Set")
            self.api_key_status_label.setStyleSheet("color: #4caf50;")
        else:
            self.api_key_status_label.setText("API Key: ✗ Not Set")
            self.api_key_status_label.setStyleSheet("color: #f44336;")
    
    def _show_api_key_dialog(self):
        dialog = ApiKeyDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            if not ApiKeyManager.has_api_key():
                QMessageBox.critical(self, "Error", "API key is required.")
                self.close()
                return
        
        api_key = dialog.get_api_key()
        if not api_key:
            QMessageBox.warning(self, "Warning", "No API key provided.")
            return
        
        if dialog.should_remember():
            try:
                ApiKeyManager.save_api_key(api_key)
                self._update_api_key_status(True)
            except Exception as e:
                QMessageBox.warning(self, "Warning", f"Could not save API key: {e}")
        
        self._initialize_client()
    
    def _initialize_client(self):
        api_key = ApiKeyManager.get_api_key()
        if not api_key:
            self._show_api_key_dialog()
            return
        
        try:
            self.vt_client = RateLimitedClient(api_key)
            self._setup_tabs()
            self.statusBar().showMessage("Connected to VirusTotal - Ready to scan!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to initialize client: {e}")
            self._show_api_key_dialog()
    
    def _setup_tabs(self):
        self.history_widget = ScanHistoryWidget(self.vt_client)
        self.manual_scan_widget = ManualScanWidget(self.vt_client, self.history_widget)
        self.auto_scan_widget = AutoScanWidget(self.vt_client, self.history_widget)
        
        # Settings widget - needs to be accessible for updates
        self.settings_widget = ApiKeySettingsWidget()
        self.settings_widget.api_key_updated.connect(self._on_api_key_updated)
        
        layout1 = QVBoxLayout()
        layout1.addWidget(self.manual_scan_widget)
        self.manual_scan_tab.setLayout(layout1)
        
        layout2 = QVBoxLayout()
        layout2.addWidget(self.auto_scan_widget)
        self.auto_scan_tab.setLayout(layout2)
        
        layout4 = QVBoxLayout()
        layout4.addWidget(self.history_widget)
        self.history_tab.setLayout(layout4)
        
        layout5 = QVBoxLayout()
        layout5.addWidget(self.settings_widget)
        self.settings_tab.setLayout(layout5)
    
    def _on_api_key_updated(self):
        api_key = ApiKeyManager.get_api_key()
        if api_key:
            self._update_api_key_status(True)
            if self.vt_client:
                self.vt_client.close()
            try:
                self.vt_client = RateLimitedClient(api_key)
                self.statusBar().showMessage("API key updated - Ready to scan!")
            except Exception as e:
                self.statusBar().showMessage(f"Error updating client: {e}")
        else:
            self._update_api_key_status(False)
            self.statusBar().showMessage("API key removed - Please add a new key")
    
    def closeEvent(self, event):
        if self.auto_scan_widget and self.auto_scan_widget.monitor:
            self.auto_scan_widget.monitor.stop()
        if self.vt_client:
            self.vt_client.close()
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLESHEET)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
