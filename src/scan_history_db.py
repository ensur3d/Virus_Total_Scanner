import sqlite3
import os
import json
import threading
from typing import Optional, List, Dict, Any
from datetime import datetime
from dataclasses import dataclass, asdict


@dataclass
class ScanRecord:
    id: Optional[int] = None
    file_path: str = ""
    file_hash: str = ""
    file_name: str = ""
    file_size: int = 0
    scan_timestamp: float = 0.0
    scan_status: str = ""
    malicious_count: int = 0
    suspicious_count: int = 0
    undetected_count: int = 0
    reputation: int = 0
    vt_id: str = ""
    vt_data: str = ""  # JSON serialized


class ScanHistoryDB:
    """SQLite database for storing scan history."""
    
    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            config_dir = os.path.expanduser("~/.config/virus_total_scanner")
            os.makedirs(config_dir, exist_ok=True)
            db_path = os.path.join(config_dir, "scan_history.db")
        
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_database()
    
    def _init_database(self):
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    file_size INTEGER,
                    scan_timestamp REAL NOT NULL,
                    scan_status TEXT NOT NULL,
                    malicious_count INTEGER DEFAULT 0,
                    suspicious_count INTEGER DEFAULT 0,
                    undetected_count INTEGER DEFAULT 0,
                    reputation INTEGER DEFAULT 0,
                    vt_id TEXT,
                    vt_data TEXT,
                    UNIQUE(file_hash)
                )
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_file_hash ON scan_history(file_hash)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scan_history(scan_timestamp DESC)
            ''')
            
            conn.commit()
            conn.close()
    
    def add_scan_record(self, record: ScanRecord) -> int:
        """Add a scan record to the database. Returns the inserted record ID."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO scan_history 
                    (file_path, file_hash, file_name, file_size, scan_timestamp, 
                     scan_status, malicious_count, suspicious_count, undetected_count, 
                     reputation, vt_id, vt_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    record.file_path,
                    record.file_hash,
                    record.file_name,
                    record.file_size,
                    record.scan_timestamp,
                    record.scan_status,
                    record.malicious_count,
                    record.suspicious_count,
                    record.undetected_count,
                    record.reputation,
                    record.vt_id,
                    record.vt_data
                ))
                
                record_id = cursor.lastrowid
                conn.commit()
                return record_id if record_id else 0
            except Exception as e:
                print(f"Error adding scan record: {e}")
                return 0
            finally:
                conn.close()
    
    def get_record_by_hash(self, file_hash: str) -> Optional[ScanRecord]:
        """Get a scan record by file hash."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM scan_history WHERE file_hash = ?', (file_hash,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return ScanRecord(**dict(row))
            return None
    
    def get_record_by_id(self, record_id: int) -> Optional[ScanRecord]:
        """Get a scan record by ID."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM scan_history WHERE id = ?', (record_id,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return ScanRecord(**dict(row))
            return None
    
    def get_all_records(self, limit: int = 100) -> List[ScanRecord]:
        """Get all scan records, ordered by timestamp (newest first)."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM scan_history 
                ORDER BY scan_timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            return [ScanRecord(**dict(row)) for row in rows]
    
    def get_recent_scans(self, hours: int = 24) -> List[ScanRecord]:
        """Get scans from the last N hours."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cutoff = datetime.now().timestamp() - (hours * 3600)
            
            cursor.execute('''
                SELECT * FROM scan_history 
                WHERE scan_timestamp >= ?
                ORDER BY scan_timestamp DESC
            ''', (cutoff,))
            
            rows = cursor.fetchall()
            conn.close()
            
            return [ScanRecord(**dict(row)) for row in rows]
    
    def search_records(self, query: str, limit: int = 50) -> List[ScanRecord]:
        """Search records by file name or path."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            search_term = f"%{query}%"
            cursor.execute('''
                SELECT * FROM scan_history 
                WHERE file_name LIKE ? OR file_path LIKE ?
                ORDER BY scan_timestamp DESC
                LIMIT ?
            ''', (search_term, search_term, limit))
            
            rows = cursor.fetchall()
            conn.close()
            
            return [ScanRecord(**dict(row)) for row in rows]
    
    def delete_record(self, record_id: int) -> bool:
        """Delete a scan record by ID."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM scan_history WHERE id = ?', (record_id,))
            deleted = cursor.rowcount > 0
            conn.commit()
            conn.close()
            
            return deleted
    
    def clear_all(self) -> bool:
        """Clear all records from the database."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM scan_history')
            conn.commit()
            conn.close()
            
            return True
    
    def get_stats(self) -> Dict[str, int]:
        """Get database statistics."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM scan_history')
            total = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM scan_history WHERE scan_status = "completed"')
            completed = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM scan_history WHERE malicious_count > 0')
            malicious = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                "total_scans": total,
                "completed_scans": completed,
                "malicious_files": malicious
            }
