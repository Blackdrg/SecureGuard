import yara
from pathlib import Path

class YaraScanner:
    def __init__(self):
        self.rules = self._load_rules()
        
    def _load_rules(self):
        """Load YARA rules from file"""
        rules_file = Path("config/rules.yar")
        if not rules_file.exists():
            self._create_default_rules(rules_file)
        
        try:
            return yara.compile(filepath=str(rules_file))
        except:
            return None
    
    def _create_default_rules(self, rules_file: Path):
        """Create default YARA rules"""
        default_rules = '''
rule Ransomware_Generic {
    strings:
        $s1 = "encrypted" nocase
        $s2 = "bitcoin" nocase
        $s3 = ".locked" nocase
    condition:
        2 of them
}

rule Trojan_Generic {
    strings:
        $s1 = "cmd.exe" nocase
        $s2 = "powershell" nocase
        $s3 = "download" nocase
    condition:
        all of them
}

rule Keylogger {
    strings:
        $s1 = "GetAsyncKeyState"
        $s2 = "keylog"
    condition:
        any of them
}
'''
        rules_file.parent.mkdir(exist_ok=True)
        rules_file.write_text(default_rules)
    
    def scan_file(self, file_path: str) -> list:
        """Scan file with YARA rules"""
        if not self.rules:
            return []
        
        try:
            matches = self.rules.match(file_path)
            return [{'rule': m.rule, 'tags': m.tags} for m in matches]
        except:
            return []
    
    def scan_memory(self, pid: int) -> list:
        """Scan process memory"""
        if not self.rules:
            return []
        
        try:
            matches = self.rules.match(pid=pid)
            return [{'rule': m.rule, 'tags': m.tags} for m in matches]
        except:
            return []
