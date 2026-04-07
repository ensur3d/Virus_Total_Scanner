import hashlib
import time
import threading
import asyncio
import os
import vt
import json
from typing import Dict, Any, Optional, Callable, List
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, Future

from scan_history_db import ScanHistoryDB, ScanRecord


class ScanStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    ERROR = "error"
    NOT_FOUND = "not_found"
    CACHED = "cached"


class ScanResult:
    def __init__(self, file_path: str, file_hash: str, status: ScanStatus,
                 data: Optional[Dict[str, Any]] = None, error: Optional[str] = None,
                 from_cache: bool = False):
        self.file_path = file_path
        self.file_hash = file_hash
        self.status = status
        self.data = data or {}
        self.error = error
        self.from_cache = from_cache
        self.timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "status": self.status.value,
            "data": self.data,
            "error": self.error,
            "timestamp": self.timestamp,
            "from_cache": self.from_cache
        }


class RateLimitedClient:
    """Client that respects 4 requests/minute rate limit using a token bucket algorithm."""
    REQUESTS_PER_MINUTE = 4
    REQUEST_INTERVAL = 60 / REQUESTS_PER_MINUTE

    def __init__(self, api_key: str, db_path: Optional[str] = None):
        self.api_key = api_key
        self.db = ScanHistoryDB(db_path)
        self._lock = threading.Lock()
        self._last_request_time = 0.0
        self._tokens = self.REQUESTS_PER_MINUTE  # Start with full token bucket
        self._last_token_refill = time.time()
        # Increased worker count to handle more concurrent scans
        self._executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix="VT_Scan")
        self._futures: List[Future] = []

    def _wait_for_rate_limit(self) -> None:
        """Wait if needed to respect rate limit using token bucket algorithm."""
        while True:
            with self._lock:
                current_time = time.time()
                
                # Refill tokens based on elapsed time
                time_elapsed = current_time - self._last_token_refill
                tokens_to_add = time_elapsed * (self.REQUESTS_PER_MINUTE / 60.0)
                self._tokens = min(self.REQUESTS_PER_MINUTE, self._tokens + tokens_to_add)
                self._last_token_refill = current_time
                
                # If we have a token, consume it and proceed
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    self._last_request_time = current_time
                    return
                
                # Calculate wait time until next token is available
                wait_time = (1.0 - self._tokens) * (60.0 / self.REQUESTS_PER_MINUTE)
            
            # Wait outside the lock
            time.sleep(wait_time)

    def get_file_hash(self, file_path: str) -> str:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _scan_file_sync(self, file_path: str, progress_callback: Optional[Callable] = None,
                        force_rescan: bool = False) -> ScanResult:
        """Synchronous scan implementation."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        file_hash = ""
        try:
            file_hash = self.get_file_hash(file_path)
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)

            # Check cache first
            if not force_rescan:
                cached = self.db.get_record_by_hash(file_hash)
                if cached:
                    if progress_callback:
                        progress_callback(ScanStatus.CACHED, f"Using cached result for: {file_name}")

                    return ScanResult(
                        file_path=file_path,
                        file_hash=file_hash,
                        status=ScanStatus.COMPLETED if cached.scan_status == "completed" else ScanStatus(cached.scan_status),
                        data=json.loads(cached.vt_data) if cached.vt_data else {},
                        from_cache=True
                    )

            # Now apply rate limiting (wait BEFORE the request)
            self._wait_for_rate_limit()

            if progress_callback:
                progress_callback(ScanStatus.IN_PROGRESS, f"Connecting to VirusTotal...")

            async def do_scan():
                async with vt.Client(self.api_key) as client:
                    if progress_callback:
                        progress_callback(ScanStatus.IN_PROGRESS, f"Uploading: {file_name}")

                    with open(file_path, "rb") as f:
                        analysis = await client.scan_file_async(f, wait_for_completion=True)

                    return analysis

            analysis = loop.run_until_complete(do_scan())

            if progress_callback:
                progress_callback(ScanStatus.COMPLETED, "Scan completed")

            result_data = {
                "id": analysis.id,
                "stats": dict(analysis.stats) if analysis.stats else {},
                "status": analysis.status,
                "type": analysis.type,
            }

            result = ScanResult(
                file_path=file_path,
                file_hash=file_hash,
                status=ScanStatus.COMPLETED,
                data=result_data
            )

            record = ScanRecord(
                file_path=file_path,
                file_hash=file_hash,
                file_name=file_name,
                file_size=file_size,
                scan_timestamp=time.time(),
                scan_status="completed",
                malicious_count=result_data.get("stats", {}).get("malicious", 0),
                suspicious_count=result_data.get("stats", {}).get("suspicious", 0),
                undetected_count=result_data.get("stats", {}).get("undetected", 0),
                reputation=0,
                vt_id=analysis.id or "",
                vt_data=json.dumps(result_data)
            )
            self.db.add_scan_record(record)

            return result

        except vt.APIError as e:
            error_msg = f"API Error: {e.message}"
            if progress_callback:
                progress_callback(ScanStatus.ERROR, error_msg)

            record = ScanRecord(
                file_path=file_path,
                file_hash=file_hash or "",
                file_name=os.path.basename(file_path),
                file_size=os.path.getsize(file_path) if os.path.exists(file_path) else 0,
                scan_timestamp=time.time(),
                scan_status="error",
                vt_data=json.dumps({"error": error_msg})
            )
            self.db.add_scan_record(record)

            return ScanResult(
                file_path=file_path,
                file_hash=file_hash or "",
                status=ScanStatus.ERROR,
                error=error_msg
            )
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            if progress_callback:
                progress_callback(ScanStatus.ERROR, error_msg)

            return ScanResult(
                file_path=file_path,
                file_hash=self.get_file_hash(file_path),
                status=ScanStatus.ERROR,
                error=error_msg
            )
        finally:
            loop.close()

    def scan_file(self, file_path: str, progress_callback: Optional[Callable] = None,
                  force_rescan: bool = False) -> ScanResult:
        """Scan a file synchronously (uses rate limiting)."""
        return self._scan_file_sync(file_path, progress_callback, force_rescan)

    def scan_file_async(self, file_path: str, progress_callback: Optional[Callable] = None,
                        force_rescan: bool = False) -> Future:
        """Submit scan to thread pool for concurrent execution."""
        future = self._executor.submit(
            self._scan_file_sync, file_path, progress_callback, force_rescan
        )
        self._futures.append(future)
        return future

    def _sync_get_file_report(self, file_hash: str, progress_callback: Optional[Callable] = None) -> ScanResult:
        """Synchronous report retrieval."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            # Check cache first
            cached = self.db.get_record_by_hash(file_hash)
            if cached:
                if progress_callback:
                    progress_callback(ScanStatus.CACHED, f"Using cached result")

                return ScanResult(
                    file_path=cached.file_path,
                    file_hash=file_hash,
                    status=ScanStatus.COMPLETED if cached.scan_status == "completed" else ScanStatus(cached.scan_status),
                    data=json.loads(cached.vt_data) if cached.vt_data else {},
                    from_cache=True
                )

            # Apply rate limiting
            self._wait_for_rate_limit()

            if progress_callback:
                progress_callback(ScanStatus.IN_PROGRESS, f"Fetching report for: {file_hash[:16]}...")

            async def do_get_report():
                async with vt.Client(self.api_key) as client:
                    return await client.get_object_async(f"/files/{file_hash}")

            file_obj = loop.run_until_complete(do_get_report())

            if progress_callback:
                progress_callback(ScanStatus.COMPLETED, "Report retrieved")

            result_data = {
                "id": file_obj.id,
                "type": file_obj.type,
                "stats": dict(file_obj.stats) if hasattr(file_obj, 'stats') and file_obj.stats else {},
                "meaningful_name": getattr(file_obj, 'meaningful_name', file_hash),
                "reputation": getattr(file_obj, 'reputation', 0),
                "last_analysis_stats": dict(file_obj.last_analysis_stats) if hasattr(file_obj, 'last_analysis_stats') else {},
                "last_analysis_results": self._extract_analysis_results(file_obj),
                "popular_threat_classification": getattr(file_obj, 'popular_threat_classification', None),
                "sandbox_verdicts": dict(file_obj.sandbox_verdicts) if hasattr(file_obj, 'sandbox_verdicts') and file_obj.sandbox_verdicts else {},
                "total_votes": dict(file_obj.total_votes) if hasattr(file_obj, 'total_votes') and file_obj.total_votes else {},
            }

            stats = result_data.get("last_analysis_stats", {})
            record = ScanRecord(
                file_path="",
                file_hash=file_hash,
                file_name=file_hash[:16] + "...",
                file_size=0,
                scan_timestamp=time.time(),
                scan_status="completed",
                malicious_count=stats.get("malicious", 0),
                suspicious_count=stats.get("suspicious", 0),
                undetected_count=stats.get("undetected", 0),
                reputation=result_data.get("reputation", 0),
                vt_id=result_data.get("id", "") or "",
                vt_data=json.dumps(result_data)
            )
            self.db.add_scan_record(record)

            return ScanResult(
                file_path="",
                file_hash=file_hash,
                status=ScanStatus.COMPLETED,
                data=result_data
            )

        except vt.APIError as e:
            if e.code == "NotFoundError":
                if progress_callback:
                    progress_callback(ScanStatus.NOT_FOUND, "File not found in VirusTotal database")
                return ScanResult(
                    file_path="",
                    file_hash=file_hash,
                    status=ScanStatus.NOT_FOUND,
                    error="File not found in VirusTotal database"
                )
            error_msg = f"API Error: {e.message}"
            if progress_callback:
                progress_callback(ScanStatus.ERROR, error_msg)
            return ScanResult(
                file_path="",
                file_hash=file_hash,
                status=ScanStatus.ERROR,
                error=error_msg
            )
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            if progress_callback:
                progress_callback(ScanStatus.ERROR, error_msg)
            return ScanResult(
                file_path="",
                file_hash=file_hash,
                status=ScanStatus.ERROR,
                error=error_msg
            )
        finally:
            loop.close()

    def get_file_report(self, file_hash: str, progress_callback: Optional[Callable] = None) -> ScanResult:
        """Get file report synchronously."""
        with self._lock:
            return self._sync_get_file_report(file_hash, progress_callback)

    def _extract_analysis_results(self, file_obj) -> Dict[str, Any]:
        results = {}
        if hasattr(file_obj, 'last_analysis_results') and file_obj.last_analysis_results:
            for engine, result in file_obj.last_analysis_results.items():
                if isinstance(result, dict):
                    results[engine] = {
                        "category": result.get("category", "unknown"),
                        "result": result.get("result", "unknown"),
                        "method": result.get("method", "unknown"),
                        "engine_version": result.get("engine_version", "unknown"),
                        "engine_update": result.get("engine_update", "unknown"),
                    }
        return results

    def get_scan_history(self) -> List[ScanRecord]:
        """Get all scan records from database."""
        return self.db.get_all_records()

    def get_cached_result(self, file_hash: str) -> Optional[ScanRecord]:
        """Get cached scan result for a file hash."""
        return self.db.get_record_by_hash(file_hash)

    def shutdown(self):
        """Shutdown the thread pool executor."""
        self._executor.shutdown(wait=True)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()
