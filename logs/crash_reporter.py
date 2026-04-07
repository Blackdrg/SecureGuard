import sys
import traceback
import platform
import requests
from datetime import datetime
from pathlib import Path

class CrashReporter:
    def __init__(self):
        self.telemetry_endpoint = "https://telemetry.secureguard.example.com"
        self.crash_dir = Path("logs/crashes")
        self.crash_dir.mkdir(parents=True, exist_ok=True)
        
    def report_crash(self, exc_type, exc_value, exc_traceback):
        """Report crash with full context"""
        crash_data = {
            'timestamp': datetime.now().isoformat(),
            'exception_type': str(exc_type.__name__),
            'exception_message': str(exc_value),
            'traceback': ''.join(traceback.format_tb(exc_traceback)),
            'platform': platform.platform(),
            'python_version': sys.version,
        }
        
        # Save locally
        crash_file = self.crash_dir / f"crash_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        import json
        crash_file.write_text(json.dumps(crash_data, indent=2))
        
        # Send to server
        try:
            requests.post(f"{self.telemetry_endpoint}/crash", json=crash_data, timeout=5)
        except:
            pass
    
    def send_telemetry(self, event_type: str, data: dict):
        """Send anonymous telemetry"""
        telemetry = {
            'event': event_type,
            'timestamp': datetime.now().isoformat(),
            'data': data
        }
        
        try:
            requests.post(f"{self.telemetry_endpoint}/event", json=telemetry, timeout=3)
        except:
            pass

def install_crash_handler():
    """Install global crash handler"""
    reporter = CrashReporter()
    sys.excepthook = reporter.report_crash
