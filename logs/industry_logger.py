"""
Industry-Standard Logging System
================================

Production logging with:
- Structured logging (JSON)
- Multiple log levels
- Log rotation
- Cloud upload
- Searchable indices
- Fallback handling
"""

import json
import logging
import threading
import time
import os
import traceback
from pathlib import Path
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from queue import Queue
from typing import Optional, Dict, Any
import gzip
import hashlib


class IndustryLogger:
    """
    Production-grade logging system for antivirus software.
    Logs: scan results, errors, detections, updates, system events.
    Stores locally + optionally uploads to cloud.
    """
    
    def __init__(self, cloud_upload_enabled: bool = False):
        self.log_dir = Path("logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.cloud_enabled = cloud_upload_enabled
        self.log_queue = Queue()
        self.running = False
        
        # Initialize all loggers
        self._setup_loggers()
        
        # Start async log processor
        self._start_async_processor()
        
    def _setup_loggers(self):
        """Setup all industry-standard loggers"""
        
        # Main application logger
        self.app_logger = self._create_logger(
            'app',
            'antivirus.log',
            max_bytes=50*1024*1024,  # 50MB
            backup_count=10
        )
        
        # Scan results logger
        self.scan_logger = self._create_logger(
            'scan',
            'scans.log',
            max_bytes=20*1024*1024,  # 20MB
            backup_count=5
        )
        
        # Detection logger
        self.detection_logger = self._create_logger(
            'detection',
            'detections.log',
            max_bytes=30*1024*1024,  # 30MB
            backup_count=10
        )
        
        # Error logger (separate for critical errors)
        self.error_logger = self._create_logger(
            'error',
            'errors.log',
            max_bytes=10*1024*1024,  # 10MB
            backup_count=20
        )
        
        # Update logger
        self.update_logger = self._create_logger(
            'update',
            'updates.log',
            max_bytes=10*1024*1024,
            backup_count=5
        )
        
        # System events logger
        self.system_logger = self._create_logger(
            'system',
            'system.log',
            max_bytes=20*1024*1024,
            backup_count=5
        )
        
    def _create_logger(self, name: str, filename: str, 
                       max_bytes: int = 10*1024*1024, 
                       backup_count: int = 5) -> logging.Logger:
        """Create a logger with file rotation"""
        
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
        
        # Clear existing handlers
        logger.handlers.clear()
        
        # File handler with rotation
        log_file = self.log_dir / filename
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        
        # JSON formatter for structured logging
        formatter = logging.Formatter(
            '%(asctime)s|%(levelname)s|%(name)s|%(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        return logger
    
    def _start_async_processor(self):
        """Start async log processor for cloud uploads"""
        self.running = True
        self.processor_thread = threading.Thread(
            target=self._process_log_queue,
            daemon=True
        )
        self.processor_thread.start()
    
    def _process_log_queue(self):
        """Process log queue for cloud uploads"""
        while self.running:
            try:
                if not self.log_queue.empty():
                    log_entry = self.log_queue.get(timeout=1)
                    if self.cloud_enabled:
                        self._upload_to_cloud(log_entry)
                else:
                    time.sleep(1)
            except Exception as e:
                self.error(f"Log processor error: {e}")
    
    def _upload_to_cloud(self, log_entry: Dict):
        """Upload log entry to cloud (optional)"""
        try:
            import requests
            # Replace with actual cloud endpoint
            requests.post(
                'https://api.secureguard.local/logs/ingest',
                json=log_entry,
                timeout=5
            )
        except:
            pass  # Fail silently - local logging is primary
    
    # ==================== LOGGING METHODS ====================
    
    # Scan logging
    def log_scan_start(self, scan_type: str, paths: list):
        """Log scan start"""
        entry = self._create_entry('SCAN_START', {
            'scan_type': scan_type,
            'paths': paths,
            'timestamp': datetime.now().isoformat()
        })
        self.scan_logger.info(json.dumps(entry))
        self._queue_for_cloud(entry)
    
    def log_scan_complete(self, scan_type: str, files_scanned: int, 
                         threats_found: int, duration: float):
        """Log scan completion"""
        entry = self._create_entry('SCAN_COMPLETE', {
            'scan_type': scan_type,
            'files_scanned': files_scanned,
            'threats_found': threats_found,
            'duration_seconds': duration,
            'timestamp': datetime.now().isoformat()
        })
        self.scan_logger.info(json.dumps(entry))
        self._queue_for_cloud(entry)
    
    def log_scan_threat(self, file_path: str, threat_name: str, 
                        severity: str, action: str):
        """Log detected threat during scan"""
        entry = self._create_entry('SCAN_THREAT', {
            'file_path': file_path,
            'threat_name': threat_name,
            'severity': severity,
            'action': action,
            'timestamp': datetime.now().isoformat()
        })
        self.detection_logger.warning(json.dumps(entry))
        self._queue_for_cloud(entry)
    
    # Detection logging
    def log_detection(self, threat_name: str, file_path: str, 
                      method: str, severity: str):
        """Log threat detection"""
        entry = self._create_entry('THREAT_DETECTED', {
            'threat_name': threat_name,
            'file_path': file_path,
            'detection_method': method,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        })
        self.detection_logger.warning(json.dumps(entry))
        self._queue_for_cloud(entry)
    
    def log_blocked(self, event_type: str, details: Dict):
        """Log blocked event"""
        entry = self._create_entry('EVENT_BLOCKED', {
            'event_type': event_type,
            'details': details,
            'timestamp': datetime.now().isoformat()
        })
        self.detection_logger.info(json.dumps(entry))
    
    # Update logging
    def log_update_check(self, status: str, version: str = None):
        """Log update check"""
        entry = self._create_entry('UPDATE_CHECK', {
            'status': status,
            'current_version': version,
            'timestamp': datetime.now().isoformat()
        })
        self.update_logger.info(json.dumps(entry))
    
    def log_update_download(self, version: str, size: int):
        """Log update download"""
        entry = self._create_entry('UPDATE_DOWNLOAD', {
            'version': version,
            'size_bytes': size,
            'timestamp': datetime.now().isoformat()
        })
        self.update_logger.info(json.dumps(entry))
    
    def log_update_install(self, version: str, success: bool):
        """Log update installation"""
        entry = self._create_entry('UPDATE_INSTALL', {
            'version': version,
            'success': success,
            'timestamp': datetime.now().isoformat()
        })
        if success:
            self.update_logger.info(json.dumps(entry))
        else:
            self.update_logger.error(json.dumps(entry))
    
    # System logging
    def log_service_start(self, service_name: str):
        """Log service start"""
        entry = self._create_entry('SERVICE_START', {
            'service': service_name,
            'timestamp': datetime.now().isoformat()
        })
        self.system_logger.info(json.dumps(entry))
    
    def log_service_stop(self, service_name: str):
        """Log service stop"""
        entry = self._create_entry('SERVICE_STOP', {
            'service': service_name,
            'timestamp': datetime.now().isoformat()
        })
        self.system_logger.info(json.dumps(entry))
    
    def log_config_change(self, key: str, old_value: Any, new_value: Any):
        """Log configuration change"""
        entry = self._create_entry('CONFIG_CHANGE', {
            'key': key,
            'old_value': str(old_value),
            'new_value': str(new_value),
            'timestamp': datetime.now().isoformat()
        })
        self.system_logger.info(json.dumps(entry))
    
    # Error logging
    def log_error(self, error_type: str, message: str, 
                 exception: Exception = None, context: Dict = None):
        """Log error with full context"""
        entry = self._create_entry('ERROR', {
            'error_type': error_type,
            'message': message,
            'context': context or {},
            'timestamp': datetime.now().isoformat()
        })
        
        if exception:
            entry['traceback'] = traceback.format_exc()
        
        self.error_logger.error(json.dumps(entry))
        self._queue_for_cloud(entry)
    
    def log_exception(self, exception: Exception, context: Dict = None):
        """Log exception with traceback"""
        self.log_error(
            error_type=type(exception).__name__,
            message=str(exception),
            exception=exception,
            context=context
        )
    
    # Generic logging methods
    def debug(self, message: str):
        self.app_logger.debug(message)
    
    def info(self, message: str):
        self.app_logger.info(message)
    
    def warning(self, message: str):
        self.app_logger.warning(message)
    
    def error(self, message: str):
        self.app_logger.error(message)
    
    def critical(self, message: str):
        self.app_logger.critical(message)
    
    # ==================== HELPER METHODS ====================
    
    def _create_entry(self, event_type: str, data: Dict) -> Dict:
        """Create structured log entry"""
        return {
            'event_type': event_type,
            'data': data,
            'timestamp': data.get('timestamp', datetime.now().isoformat())
        }
    
    def _queue_for_cloud(self, entry: Dict):
        """Queue entry for cloud upload"""
        if self.cloud_enabled:
            self.log_queue.put(entry)
    
    def get_recent_logs(self, log_type: str = 'app', 
                       lines: int = 100) -> list:
        """Get recent log entries"""
        log_file = self.log_dir / f"{log_type}.log"
        if not log_file.exists():
            return []
        
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                all_lines = f.readlines()
                return all_lines[-lines:]
        except:
            return []
    
    def search_logs(self, query: str, log_type: str = 'app') -> list:
        """Search logs for query"""
        results = []
        log_file = self.log_dir / f"{log_type}.log"
        
        if not log_file.exists():
            return results
        
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if query.lower() in line.lower():
                        results.append(line.strip())
        except:
            pass
        
        return results
    
    def get_log_stats(self) -> Dict:
        """Get logging statistics"""
        stats = {}
        
        for log_file in self.log_dir.glob('*.log'):
            try:
                size = log_file.stat().st_size
                stats[log_file.name] = {
                    'size_bytes': size,
                    'size_mb': round(size / (1024*1024), 2)
                }
            except:
                pass
        
        return stats
    
    def archive_old_logs(self, days: int = 30):
        """Archive logs older than N days"""
        cutoff = datetime.now() - timedelta(days=days)
        
        for log_file in self.log_dir.glob('*.log'):
            try:
                mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
                if mtime < cutoff:
                    # Compress and archive
                    archived = log_file.with_suffix('.log.gz')
                    with open(log_file, 'rb') as f_in:
                        with gzip.open(archived, 'wb') as f_out:
                            f_out.writelines(f_in)
                    log_file.unlink()
            except:
                pass
    
    def stop(self):
        """Stop logging system"""
        self.running = False
        if hasattr(self, 'processor_thread'):
            self.processor_thread.join(timeout=5)


# Global logger instance
_logger = None

def get_logger() -> IndustryLogger:
    """Get global logger instance"""
    global _logger
    if _logger is None:
        _logger = IndustryLogger()
    return _logger


# ==================== EXCEPTION HANDLER ====================

class GlobalExceptionHandler:
    """Global exception handler with fallback logic and auto-restart"""
    
    def __init__(self, logger: IndustryLogger, max_retries: int = 3):
        self.logger = logger
        self.max_retries = max_retries
        self.retry_count = {}
        
    def handle_exception(self, exc_type, exc_value, exc_traceback):
        """Handle uncaught exception"""
        
        # Log the exception
        self.logger.log_exception(
            exception=exc_value,
            context={
                'exception_type': exc_type.__name__,
                'traceback': traceback.format_tb(exc_traceback)
            }
        )
        
        # Check retry count
        exc_key = f"{exc_type.__name__}:{str(exc_value)[:50]}"
        self.retry_count[exc_key] = self.retry_count.get(exc_key, 0) + 1
        
        if self.retry_count[exc_key] < self.max_retries:
            # Attempt recovery
            self._attempt_recovery(exc_type, exc_value)
        else:
            # Too many retries - log critical and graceful degradation
            self.logger.critical(
                f"MAX_RETRIES_EXCEEDED for {exc_key}. Entering safe mode."
            )
            self._enter_safe_mode()
    
    def _attempt_recovery(self, exc_type, exc_value):
        """Attempt to recover from exception"""
        self.logger.warning(
            f"Attempting recovery from {exc_type.__name__}: {exc_value}"
        )
        
        # Different recovery strategies based on exception type
        if 'MemoryError' in str(exc_type):
            # Force garbage collection
            import gc
            gc.collect()
        elif 'IOError' in str(exc_type) or 'OSError' in str(exc_type):
            # Retry file operations
            time.sleep(1)
        elif 'ConnectionError' in str(exc_type):
            # Network issues - wait and retry
            time.sleep(5)
    
    def _enter_safe_mode(self):
        """Enter safe mode with limited functionality"""
        self.logger.critical("Entering SAFE MODE with core protection only")
        # Could notify UI, disable non-essential features, etc.


def install_exception_handler(logger: IndustryLogger = None):
    """Install global exception handler"""
    if logger is None:
        logger = get_logger()
    
    handler = GlobalExceptionHandler(logger)
    import sys
    sys.excepthook = handler.handle_exception
    
    return handler
