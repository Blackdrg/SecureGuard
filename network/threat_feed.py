import requests
import threading
import time
from datetime import datetime

class ThreatFeed:
    def __init__(self):
        self.feeds = {
            'abuse_ch': 'https://urlhaus-api.abuse.ch/v1/urls/recent/',
            'alienvault': 'https://otx.alienvault.com/api/v1/pulses/subscribed',
        }
        self.threat_cache = {}
        self.running = False
        
    def start_feed_updates(self):
        """Start continuous threat feed updates"""
        self.running = True
        threading.Thread(target=self._update_loop, daemon=True).start()
    
    def _update_loop(self):
        """Background thread for feed updates"""
        while self.running:
            self._fetch_all_feeds()
            time.sleep(3600)  # Update hourly
    
    def _fetch_all_feeds(self):
        """Fetch from all threat feeds"""
        for feed_name, feed_url in self.feeds.items():
            try:
                response = requests.get(feed_url, timeout=10)
                if response.status_code == 200:
                    self._process_feed(feed_name, response.json())
            except:
                pass
    
    def _process_feed(self, feed_name: str, data: dict):
        """Process threat feed data"""
        self.threat_cache[feed_name] = {
            'timestamp': datetime.now().isoformat(),
            'data': data
        }
    
    def check_url(self, url: str) -> dict:
        """Check if URL is malicious"""
        for feed_name, feed_data in self.threat_cache.items():
            if 'urls' in feed_data.get('data', {}):
                for threat_url in feed_data['data']['urls']:
                    if url in str(threat_url):
                        return {
                            'malicious': True,
                            'source': feed_name,
                            'threat_type': 'malicious_url'
                        }
        return {'malicious': False}
    
    def check_ip(self, ip: str) -> dict:
        """Check if IP is malicious"""
        for feed_name, feed_data in self.threat_cache.items():
            if 'ips' in feed_data.get('data', {}):
                if ip in feed_data['data']['ips']:
                    return {
                        'malicious': True,
                        'source': feed_name,
                        'threat_type': 'malicious_ip'
                    }
        return {'malicious': False}
    
    def stop(self):
        self.running = False
