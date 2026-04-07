import os
import time
import threading
from typing import Callable, Optional, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent


class DownloadEventHandler(FileSystemEventHandler):
    def __init__(self, callback: Callable[[str], None], ignore_extensions: Optional[Set[str]] = None):
        super().__init__()
        self.callback = callback
        self.ignore_extensions = ignore_extensions or {'.tmp', '.crdownload', '.part', '.partial'}
        self._processing_files: Set[str] = set()
        self._lock = threading.Lock()
    
    def _should_process(self, path: str) -> bool:
        ext = os.path.splitext(path)[1].lower()
        if ext in self.ignore_extensions:
            return False
        
        filename = os.path.basename(path)
        if filename.startswith('.') or filename.startswith('.'):
            return False
        
        return True
    
    def _wait_for_file_ready(self, path: str, max_wait: int = 30) -> bool:
        start_time = time.time()
        last_size = -1
        
        while time.time() - start_time < max_wait:
            try:
                current_size = os.path.getsize(path)
                if current_size == last_size and current_size > 0:
                    time.sleep(1)
                    return True
                last_size = current_size
                time.sleep(0.5)
            except (OSError, FileNotFoundError):
                return False
        
        return False
    
    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        
        path = event.src_path
        
        if not self._should_process(path):
            return
        
        with self._lock:
            if path in self._processing_files:
                return
            self._processing_files.add(path)
        
        def process_file():
            try:
                if self._wait_for_file_ready(path):
                    time.sleep(1)
                    self.callback(path)
            finally:
                with self._lock:
                    self._processing_files.discard(path)
        
        thread = threading.Thread(target=process_file, daemon=True)
        thread.start()
    
    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        
        path = event.src_path
        
        if not self._should_process(path):
            return
        
        with self._lock:
            if path in self._processing_files:
                return


class DownloadMonitor:
    def __init__(self, download_path: Optional[str] = None, callback: Optional[Callable[[str], None]] = None):
        if download_path is None:
            download_path = os.path.expanduser("~/Downloads")
        
        self.download_path = download_path
        self.callback = callback
        self._observer: Optional[Observer] = None
        self._event_handler: Optional[DownloadEventHandler] = None
        self._running = False
        self._scanned_files: Set[str] = set()
        self._lock = threading.Lock()
    
    def start(self) -> bool:
        if self._running:
            return False
        
        if not os.path.exists(self.download_path):
            os.makedirs(self.download_path, exist_ok=True)
        
        self._event_handler = DownloadEventHandler(self._handle_new_file)
        self._observer = Observer()
        self._observer.schedule(self._event_handler, self.download_path, recursive=False)
        self._observer.start()
        self._running = True
        
        thread = threading.Thread(target=self._scan_existing_files, daemon=True)
        thread.start()
        
        return True
    
    def stop(self) -> None:
        if not self._running:
            return
        
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None
        
        self._running = False
    
    def is_running(self) -> bool:
        return self._running
    
    def _scan_existing_files(self) -> None:
        time.sleep(2)
        
        try:
            with os.scandir(self.download_path) as entries:
                for entry in entries:
                    if entry.is_file():
                        with self._lock:
                            if entry.path not in self._scanned_files:
                                self._scanned_files.add(entry.path)
                                if self.callback:
                                    self.callback(entry.path)
        except Exception:
            pass
    
    def _handle_new_file(self, path: str) -> None:
        with self._lock:
            if path in self._scanned_files:
                return
            self._scanned_files.add(path)
        
        if self.callback:
            self.callback(path)
    
    def get_scanned_files(self) -> Set[str]:
        with self._lock:
            return self._scanned_files.copy()
    
    def clear_scanned_files(self) -> None:
        with self._lock:
            self._scanned_files.clear()
