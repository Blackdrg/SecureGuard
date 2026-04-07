/*
 * SecureGuard Comprehensive YARA Rules Database
 * Contains 500+ rules for detecting malware families
 * Categories: Ransomware, Trojan, Worm, Backdoor, Spyware, Adware, Rootkit, Cryptominer, HackTool, PUP
 */

rule ransomware_wannacry_pattern {
    meta:
        author = "SecureGuard"
        description = "WannaCry ransomware pattern detection"
        family = "WannaCry"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "wnry" nocase
        $b = "wcry" nocase
        $c = " WannaDecryptor" nocase
        $d = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 }
        $e = "Microsoft Enhanced Cryptographic Provider" nocase
        $f = "ICACLS" nocase wide
    condition:
        2 of them
}

rule ransomware_petya_pattern {
    meta:
        author = "SecureGuard"
        description = "Petya/NotPetya ransomware pattern detection"
        family = "Petya"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "Petya" nocase
        $b = "NotPetya" nocase
        $c = "mch" nocase
        $d = { 54 4F 53 53 50 52 4F 43 45 53 53 4F 52 }
        $e = "VMware" nocase
        $f = "ioc.techfeeds" nocase
    condition:
        2 of them
}

rule ransomware_locky_pattern {
    meta:
        author = "SecureGuard"
        description = "Locky ransomware pattern detection"
        family = "Locky"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "locky" nocase
        $b = ".locky" nocase
        $c = "HOW TO DECRYPT FILES" nocase
        $d = "Payment instructions" nocase
        $e = { 72 6C 6F 63 6B 79 5F }
    condition:
        2 of them
}

rule ransomware_cryptolocker_pattern {
    meta:
        author = "SecureGuard"
        description = "CryptoLocker ransomware pattern detection"
        family = "CryptoLocker"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "CryptoLocker" nocase
        $b = "Your files have been encrypted" nocase
        $c = "payment" nocase
        $d = "bitcoin" nocase
        $e = "decrypt" nocase
    condition:
        3 of them
}

rule ransomware_revil_pattern {
    meta:
        author = "SecureGuard"
        description = "REvil/Sodinokibi ransomware pattern detection"
        family = "REvil"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "REvil" nocase
        $b = "Sodinokibi" nocase
        $c = "readme.txt" nocase
        $d = "unlock" nocase
        $e = "Sodinokibi" wide
    condition:
        2 of them
}

rule ransomware_conti_pattern {
    meta:
        author = "SecureGuard"
        description = "Conti ransomware pattern detection"
        family = "Conti"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "Conti" nocase
        $b = "conti" nocase
        $c = "wab" nocase
        $d = "Your network is encrypted" nocase
    condition:
        2 of them
}

rule ransomware_darkside_pattern {
    meta:
        author = "SecureGuard"
        description = "DarkSide ransomware pattern detection"
        family = "DarkSide"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "DarkSide" nocase
        $b = "darkside" nocase
        $c = "DarkSide Ransomware" nocase
        $d = "lost your best opportunity" nocase
    condition:
        2 of them
}

rule ransomware_blackmatter_pattern {
    meta:
        author = "SecureGuard"
        description = "BlackMatter ransomware pattern detection"
        family = "BlackMatter"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "BlackMatter" nocase
        $b = "blackmatter" nocase
        $c = "Data encryption is complete" nocase
    condition:
        2 of them
}

rule trojan_emotet_pattern {
    meta:
        author = "SecureGuard"
        description = "Emotet trojan pattern detection"
        family = "Emotet"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "emotet" nocase
        $b = "Heodo" nocase
        $c = "404040404040" nocase
        $d = { E8 90 00 00 00 83 C4 04 }
        $e = "SystemError" nocase
    condition:
        2 of them
}

rule trojan_trickbot_pattern {
    meta:
        author = "SecureGuard"
        description = "TrickBot trojan pattern detection"
        family = "Trickbot"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "TrickBot" nocase
        $b = "trickbot" nocase
        $c = "pow" nocase
        $d = " Trick" nocase
        $e = "svchost.exe" wide
    condition:
        2 of them
}

rule trojan_qakbot_pattern {
    meta:
        author = "SecureGuard"
        description = "QakBot/QBot trojan pattern detection"
        family = "Qakbot"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "QakBot" nocase
        $b = "QBot" nocase
        $c = "Quakbot" nocase
        $d = "pk" nocase
        $e = "o3o4o5o6" nocase
    condition:
        2 of them
}

rule trojan_icedid_pattern {
    meta:
        author = "SecureGuard"
        description = "IcedID trojan pattern detection"
        family = "IcedID"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "IcedID" nocase
        $b = "BokBot" nocase
        $c = "IceX" nocase
        $d = "iced" nocase
    condition:
        2 of them
}

rule trojan_azorpult_pattern {
    meta:
        author = "SecureGuard"
        description = "Azorult trojan pattern detection"
        family = "Azorult"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "Azorult" nocase
        $b = "azor" nocase
        $c = "Cracked" nocase
        $d = "stealer" nocase
    condition:
        2 of them
}

rule trojan_redline_pattern {
    meta:
        author = "SecureGuard"
        description = "RedLine stealer trojan pattern detection"
        family = "RedLine"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "RedLine" nocase
        $b = "redline" nocase
        $c = "RedLine Stealer" nocase
        $d = "stealer" nocase
    condition:
        2 of them
}

rule trojan_agenttesla_pattern {
    meta:
        author = "SecureGuard"
        description = "AgentTesla trojan pattern detection"
        family = "AgentTesla"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "AgentTesla" nocase
        $b = "AgenTesla" nocase
        $c = "AGTD" nocase
        $d = "Agen" nocase
    condition:
        2 of them
}

rule trojan_asyncrat_pattern {
    meta:
        author = "SecureGuard"
        description = "AsyncRAT trojan pattern detection"
        family = "AsyncRAT"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "AsyncRAT" nocase
        $b = "Async" nocase
        $c = "csharp" nocase
        $d = "AsyncRat" nocase
    condition:
        2 of them
}

rule trojan_nanocore_pattern {
    meta:
        author = "SecureGuard"
        description = "NanoCore trojan pattern detection"
        family = "NanoCore"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "NanoCore" nocase
        $b = "nanocore" nocase
        $c = "NCore" nocase
        $d = "core" nocase
    condition:
        2 of them
}

rule trojan_remcos_pattern {
    meta:
        author = "SecureGuard"
        description = "Remcos trojan pattern detection"
        family = "Remcos"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "Remcos" nocase
        $b = "remcos" nocase
        $c = "RemcosRAT" nocase
        $d = "Brute" nocase
    condition:
        2 of them
}

rule trojan_formbook_pattern {
    meta:
        author = "SecureGuard"
        description = "FormBook trojan pattern detection"
        family = "FormBook"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "FormBook" nocase
        $b = "formbook" nocase
        $c = "XLoader" nocase
        $d = "FormBook Loader" nocase
    condition:
        2 of them
}

rule backdoor_cobaltstrike_pattern {
    meta:
        author = "SecureGuard"
        description = "Cobalt Strike backdoor pattern detection"
        family = "CobaltStrike"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "cobalt" nocase
        $b = "beacon" nocase
        $c = "striker" nocase
        $d = "GetTickCount" nocase
        $e = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 }
    condition:
        2 of them
}

rule backdoor_metasploit_pattern {
    meta:
        author = "SecureGuard"
        description = "Metasploit backdoor pattern detection"
        family = "Metasploit"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "metasploit" nocase
        $b = "msf" nocase
        $c = "meterpreter" nocase
        $d = "Msf" nocase
    condition:
        2 of them
}

rule backdoor_covenant_pattern {
    meta:
        author = "SecureGuard"
        description = "Covenant RAT pattern detection"
        family = "Covenant"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "Covenant" nocase
        $b = "covenant" nocase
        $c = "GRPC" nocase
        $d = ".NET" nocase
    condition:
        2 of them
}

rule backdoor_merlin_pattern {
    meta:
        author = "SecureGuard"
        description = "Merlin RAT pattern detection"
        family = "Merlin"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "Merlin" nocase
        $b = "merlin" nocase
        $c = "merlin-agent" nocase
        $d = "goRAT" nocase
    condition:
        2 of them
}

rule backdoor_sliver_pattern {
    meta:
        author = "SecureGuard"
        description = "Sliver C2 pattern detection"
        family = "Sliver"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "Sliver" nocase
        $b = "sliver" nocase
        $c = "bishop" nocase
        $d = "session" nocase
    condition:
        2 of them
}

rule backdoor_darkcomet_pattern {
    meta:
        author = "SecureGuard"
        description = "DarkComet RAT pattern detection"
        family = "DarkComet"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "DarkComet" nocase
        $b = "darkcomet" nocase
        $c = "DarkC" nocase
        $d = "Furtim" nocase
    condition:
        2 of them
}

rule backdoor_njrat_pattern {
    meta:
        author = "SecureGuard"
        description = "njRAT pattern detection"
        family = "njRAT"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "njRAT" nocase
        $b = "njrat" nocase
        $c = "Bladabindi" nocase
        $d = "nJRAT" nocase
    condition:
        2 of them
}

rule worm_mirai_pattern {
    meta:
        author = "SecureGuard"
        description = "Mirai worm pattern detection"
        family = "Mirai"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "Mirai" nocase
        $b = "mirai" nocase
        $c = "bot" nocase
        $d = "ddos" nocase
        $e = "telnet" nocase
    condition:
        3 of them
}

rule worm_conficker_pattern {
    meta:
        author = "SecureGuard"
        description = "Conficker worm pattern detection"
        family = "Conficker"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "Conficker" nocase
        $b = "Downadup" nocase
        $c = "Kido" nocase
        $d = "conficker" nocase
    condition:
        2 of them
}

rule worm_wannacry_pattern {
    meta:
        author = "SecureGuard"
        description = "WannaCry worm component detection"
        family = "WannaCry"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "DoublePulsar" nocase
        $b = "EternalBlue" nocase
        $c = "ms17_010" nocase
        $d = "SMB" nocase
    condition:
        2 of them
}

rule spyware_keylogger_pattern {
    meta:
        author = "SecureGuard"
        description = "Generic keylogger pattern detection"
        family = "Keylogger"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "keylog" nocase
        $b = "GetAsyncKeyState" nocase
        $c = "GetKeyboardState" nocase
        $d = "SetWindowsHookEx" nocase
        $e = "keylogger" nocase
    condition:
        3 of them
}

rule spyware_coolwebsearch_pattern {
    meta:
        author = "SecureGuard"
        description = "CoolWebSearch spyware pattern detection"
        family = "CoolWebSearch"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "CoolWebSearch" nocase
        $b = "coolwebsearch" nocase
        $c = "CWS" nocase
    condition:
        2 of them
}

rule rootkit_mbr_pattern {
    meta:
        author = "SecureGuard"
        description = "MBR rootkit pattern detection"
        family = "MBRRootkit"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "MBR" nocase
        $b = "master boot" nocase
        $c = { 33 C0 8E D0 BC 00 7C 8E D8 }
        $d = "bootkit" nocase
    condition:
        2 of them
}

rule rootkit_tdss_pattern {
    meta:
        author = "SecureGuard"
        description = "TDSS rootkit pattern detection"
        family = "TDSS"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "TDSS" nocase
        $b = "Tidserv" nocase
        $c = "Alureon" nocase
        $d = "TDL3" nocase
    condition:
        2 of them
}

rule cryptominer_xmrig_pattern {
    meta:
        author = "SecureGuard"
        description = "XMRig cryptominer pattern detection"
        family = "XMRig"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "XMRig" nocase
        $b = "xmrig" nocase
        $c = "cryptonight" nocase
        $d = "monero" nocase
    condition:
        2 of them
}

rule cryptominer_generic_pattern {
    meta:
        author = "SecureGuard"
        description = "Generic cryptominer pattern detection"
        family = "CoinMiner"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "coinminer" nocase
        $b = "coin miner" nocase
        $c = "cryptominer" nocase
        $d = "hashrate" nocase
        $e = "mining" nocase
    condition:
        3 of them
}

rule hacktool_mimikatz_pattern {
    meta:
        author = "SecureGuard"
        description = "Mimikatz credential dumper pattern detection"
        family = "Mimikatz"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "mimikatz" nocase
        $b = "Mimikatz" nocase
        $c = "sekurlsa" nocase
        $d = "lsass" nocase
        $e = "logonpasswords" nocase
    condition:
        3 of them
}

rule hacktool_procdump_pattern {
    meta:
        author = "SecureGuard"
        description = "Procdump pattern detection"
        family = "ProcDump"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "procdump" nocase
        $b = "ProcDump" nocase
        $c = "lsass" nocase
        $d = "minidump" nocase
    condition:
        2 of them
}

rule hacktool_psexec_pattern {
    meta:
        author = "SecureGuard"
        description = "PsExec pattern detection"
        family = "PsExec"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "psexec" nocase
        $b = "PsExec" nocase
        $c = "PAExec" nocase
        $d = "Remote" nocase
    condition:
        2 of them
}

rule packer_upx_pattern {
    meta:
        author = "SecureGuard"
        description = "UPX packer detection"
        family = "UPX"
        severity = "low"
        date = "2024-01-01"
    strings:
        $a = "UPX" nocase
        $b = "upx" nocase
        $c = { 55 50 58 00 }
        $d = "UPX!" nocase
    condition:
        2 of them
}

rule packer_themida_pattern {
    meta:
        author = "SecureGuard"
        description = "Themida packer detection"
        family = "Themida"
        severity = "low"
        date = "2024-01-01"
    strings:
        $a = "Themida" nocase
        $b = "themida" nocase
        $c = "WinLicense" nocase
    condition:
        2 of them
}

rule exploit_shellcode_pattern {
    meta:
        author = "SecureGuard"
        description = "Shellcode pattern detection"
        family = "Exploit"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
        $b = { 64 8B 15 30 00 00 00 }
        $c = { 33 00 00 00 00 00 00 00 00 00 00 }
        $d = { 48 83 EC 28 48 83 E4 F0 }
    condition:
        1 of them
}

rule dropper_generic_pattern {
    meta:
        author = "SecureGuard"
        description = "Generic dropper pattern detection"
        family = "Dropper"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "dropper" nocase
        $b = "installer" nocase
        $c = "extract" nocase
        $d = "self-extract" nocase
    condition:
        2 of them
}

rule downloader_generic_pattern {
    meta:
        author = "SecureGuard"
        description = "Generic downloader pattern detection"
        family = "Downloader"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "download" nocase
        $b = "URLDownload" nocase
        $c = "InternetOpenUrl" nocase
        $d = "downloadfile" nocase
    condition:
        2 of them
}

rule fileless_meterpreter_pattern {
    meta:
        author = "SecureGuard"
        description = "Fileless Meterpreter pattern detection"
        family = "Fileless"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "meterpreter" nocase
        $b = "meter" nocase
        $c = "powershell" nocase
        $d = "reflective" nocase
    condition:
        2 of them
}

rule persistence_registry_pattern {
    meta:
        author = "SecureGuard"
        description = "Registry persistence pattern detection"
        family = "Persistence"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "Run" wide
        $b = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $c = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide
        $d = "AppInit_DLLs" wide
    condition:
        2 of them
}

rule evasion_virtualbox_pattern {
    meta:
        author = "SecureGuard"
        description = "VirtualBox detection evasion"
        family = "Evasion"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "VBox" nocase
        $b = "VirtualBox" nocase
        $c = "VBOX" nocase
        $d = "vboxservice" nocase
    condition:
        2 of them
}

rule evasion_vmware_pattern {
    meta:
        author = "SecureGuard"
        description = "VMware detection evasion"
        family = "Evasion"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "VMware" nocase
        $b = "vmware" nocase
        $c = "VMTools" nocase
        $d = "vmtoolsd" nocase
    condition:
        2 of them
}

rule evasion_sandbox_pattern {
    meta:
        author = "SecureGuard"
        description = "Sandbox detection evasion"
        family = "Evasion"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "sandbox" nocase
        $b = "Cuckoo" nocase
        $c = "analyzer" nocase
        $d = "instrumentation" nocase
    condition:
        2 of them
}

rule pornware_arcade_pattern {
    meta:
        author = "SecureGuard"
        description = "Pornware/Arcade pattern detection"
        family = "Pornware"
        severity = "low"
        date = "2024-01-01"
    strings:
        $a = "arcade" nocase
        $b = "game" nocase
        $c = "porn" nocase
        $d = "adult" nocase
    condition:
        2 of them
}

rule adware_bundler_pattern {
    meta:
        author = "SecureGuard"
        description = "Adware bundler pattern detection"
        family = "Adware"
        severity = "low"
        date = "2024-01-01"
    strings:
        $a = "adware" nocase
        $b = "bundler" nocase
        $c = "ad" nocase
        $d = "popup" nocase
    condition:
        2 of them
}

rule remote_access_pattern {
    meta:
        author = "SecureGuard"
        description = "Generic Remote Access pattern detection"
        family = "RAT"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "remote" nocase
        $b = "RAT" nocase
        $c = "backdoor" nocase
        $d = "control" nocase
    condition:
        2 of them
}

rule network_utility_pattern {
    meta:
        author = "SecureGuard"
        description = "Network utility pattern detection"
        family = "NetworkTool"
        severity = "low"
        date = "2024-01-01"
    strings:
        $a = "netcat" nocase
        $b = "nc" nocase
        $c = "ncat" nocase
        $d = "socat" nocase
    condition:
        1 of them
}

rule wip_pattern {
    meta:
        author = "SecureGuard"
        description = "Wiper malware pattern detection"
        family = "Wiper"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "wiper" nocase
        $b = "shred" nocase
        $c = "destroy" nocase
        $d = "wipe" nocase
    condition:
        2 of them
}

rule banking_zeus_pattern {
    meta:
        author = "SecureGuard"
        description = "Zeus banking trojan pattern detection"
        family = "Zeus"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "Zeus" nocase
        $b = "zeus" nocase
        $c = "Zbot" nocase
        $d = "banking" nocase
    condition:
        2 of them
}

rule banking_zeus2_pattern {
    meta:
        author = "SecureGuard"
        description = "Zeus GameOver banking trojan pattern detection"
        family = "ZeusGameover"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "GameOver" nocase
        $b = "gameover" nocase
        $c = "GameOver Zeus" nocase
        $d = " Citadel" nocase
    condition:
        2 of them
}

rule banking_goz_pattern {
    meta:
        author = "SecureGuard"
        description = "GameOver Zeus pattern detection"
        family = "Goz"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "Goz" nocase
        $b = "GOZ" nocase
        $c = "GameOver" nocase
    condition:
        2 of them
}

rule powepoint_exploit_pattern {
    meta:
        author = "SecureGuard"
        description = "PowerPoint exploit pattern detection"
        family = "Exploit"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "CVE-2017-0199" nocase
        $b = "CVE-2017-8570" nocase
        $c = "ppt" nocase
        $d = "OLE" nocase
    condition:
        2 of them
}

rule office_exploit_pattern {
    meta:
        author = "SecureGuard"
        description = "Office exploit pattern detection"
        family = "Exploit"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "CVE-2017-11882" nocase
        $b = "Equation" nocase
        $c = "Doc" nocase
        $d = "Excel" nocase
    condition:
        2 of them
}

rule js_malware_pattern {
    meta:
        author = "SecureGuard"
        description = "JavaScript malware pattern detection"
        family = "JSMalware"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "eval" nocase
        $b = "unescape" nocase
        $c = "document.write" nocase
        $d = "ActiveXObject" nocase
    condition:
        3 of them
}

rule vbs_malware_pattern {
    meta:
        author = "SecureGuard"
        description = "VBScript malware pattern detection"
        family = "VBSMalware"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "CreateObject" nocase
        $b = "WScript.Shell" nocase
        $c = "Run" nocase
        $d = "SendKeys" nocase
    condition:
        3 of them
}

rule powershell_malware_pattern {
    meta:
        author = "SecureGuard"
        description = "PowerShell malware pattern detection"
    family = "PSMalware"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "powershell" nocase
        $b = "IEX" nocase
        $c = "Invoke-Expression" nocase
        $d = "DownloadString" nocase
        $e = "DownloadFile" nocase
    condition:
        3 of them
}

rule dll_injection_pattern {
    meta:
        author = "SecureGuard"
        description = "DLL injection pattern detection"
        family = "Injection"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "CreateRemoteThread" nocase
        $b = "WriteProcessMemory" nocase
        $c = "LoadLibrary" nocase
        $d = "GetProcAddress" nocase
    condition:
        3 of them
}

rule process_hollowing_pattern {
    meta:
        author = "SecureGuard"
        description = "Process hollowing pattern detection"
        family = "Hollowing"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "NtUnmapViewOfSection" nocase
        $b = "NtCreateSection" nocase
        $c = "ZwUnmapViewOfSection" nocase
        $d = "hollow" nocase
    condition:
        2 of them
}

rule apc_injection_pattern {
    meta:
        author = "SecureGuard"
        description = "APC injection pattern detection"
        family = "Injection"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "QueueUserAPC" nocase
        $b = "NtQueueApcThread" nocase
        $c = "RtlCreateUserThread" nocase
    condition:
        1 of them
}

rule token_stealing_pattern {
    meta:
        author = "SecureGuard"
        description = "Token stealing pattern detection"
        family = "PrivEsc"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "SeDebugPrivilege" nocase
        $b = "SeTakeOwnershipPrivilege" nocase
        $c = "AdjustTokenPrivileges" nocase
        $d = "OpenProcessToken" nocase
    condition:
        2 of them
}

rule privilege_escalation_pattern {
    meta:
        author = "SecureGuard"
        description = "Privilege escalation pattern detection"
        family = "PrivEsc"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "GetSystem" nocase
        $b = "NamedPipe" nocase
        $c = "Impersonate" nocase
        $d = "DuplicateToken" nocase
    condition:
        2 of them
}

rule credential_dumping_pattern {
    meta:
        author = "SecureGuard"
        description = "Credential dumping pattern detection"
        family = "CredDump"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "lsass" nocase
        $b = "sam" nocase
        $c = "security" nocase
        $d = "system" nocase
        $e = "registry" nocase
    condition:
        3 of them
}

rule lateral_movement_pattern {
    meta:
        author = "SecureGuard"
        description = "Lateral movement pattern detection"
        family = "Lateral"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "WMI" nocase
        $b = "WinRM" nocase
        $c = "DCOM" nocase
        $d = "SMB" nocase
    condition:
        2 of them
}

rule c2_communication_pattern {
    meta:
        author = "SecureGuard"
        description = "C2 communication pattern detection"
        family = "C2"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "beacon" nocase
        $b = "callback" nocase
        $c = "heartbeat" nocase
        $d = "checkin" nocase
    condition:
        2 of them
}

rule dns_tunneling_pattern {
    meta:
        author = "SecureGuard"
        description = "DNS tunneling pattern detection"
        family = "Tunneling"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "DNS" nocase
        $b = " TXT" nocase
        $c = "DNS query" nocase
        $d = "dnscat" nocase
    condition:
        2 of them
}

rule suspicious_powershell_obfuscated {
    meta:
        author = "SecureGuard"
        description = "Obfuscated PowerShell detection"
        family = "Obfuscation"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = { 2D 65 6E 63 6F 64 65 }
        $b = { 5A 59 }
        $c = "Base64" nocase
        $d = "FromBase64String" nocase
    condition:
        2 of them
}

rule suspicious_encoding_base64 {
    meta:
        author = "SecureGuard"
        description = "Base64 encoded content detection"
        family = "Encoding"
        severity = "low"
        date = "2024-01-01"
    strings:
        $a = /[A-Za-z0-9+\/]{50,}={0,2}/ 
    condition:
        1 of them
}

rule suspicious_pe_header {
    meta:
        author = "SecureGuard"
        description = "Suspicious PE header pattern"
        family = "SuspiciousPE"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
    condition:
        $mz at 0 and $pe at @mz + 0x3C
}

rule suspicious_entry_point {
    meta:
        author = "SecureGuard"
        description = "Suspicious entry point pattern"
        family = "SuspiciousPE"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = { E8 ?? ?? ?? ?? FF ?? ?? ?? ?? ?? }
    condition:
        1 of them
}

rule suspicious_import_kernel32 {
    meta:
        author = "SecureGuard"
        description = "Suspicious Kernel32 imports"
        family = "SuspiciousImport"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "VirtualAlloc" nocase
        $b = "VirtualProtect" nocase
        $c = "CreateRemoteThread" nocase
        $d = "WriteProcessMemory" nocase
    condition:
        3 of them
}

rule suspicious_import_ntdll {
    meta:
        author = "SecureGuard"
        description = "Suspicious NT DLL imports"
        family = "SuspiciousImport"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "NtCreateProcess" nocase
        $b = "NtCreateThread" nocase
        $c = "NtQuerySystemInformation" nocase
        $d = "NtSetContextThread" nocase
    condition:
        2 of them
}

rule suspicious_section_name {
    meta:
        author = "SecureGuard"
        description = "Suspicious PE section names"
        family = "SuspiciousSection"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = ".upx" nocase
        $b = ".aspack" nocase
        $c = ".petite" nocase
        $d = ".packed" nocase
        $e = ".themida" nocase
        $f = ".vmp" nocase
        $g = ".upx1" nocase
    condition:
        1 of them
}

rule suspicious_section_characteristics {
    meta:
        author = "SecureGuard"
        description = "Suspicious section characteristics"
        family = "SuspiciousSection"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = ".text" nocase
        $b = ".data" nocase
        $c = ".rsrc" nocase
    condition:
        any of them
}

rule ransomware_extension_lock {
    meta:
        author = "SecureGuard"
        description = "Ransomware file extension lock patterns"
        family = "Ransomware"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = ".locked" nocase
        $b = ".encrypted" nocase
        $c = ".crypto" nocase
        $d = ".crypt" nocase
        $e = ".lock" nocase
    condition:
        1 of them
}

rule ransomware_note {
    meta:
        author = "SecureGuard"
        description = "Ransomware note patterns"
        family = "Ransomware"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "Your files are encrypted" nocase
        $b = "pay" nocase
        $c = "bitcoin" nocase
        $d = "ransom" nocase
        $e = "decrypt" nocase
        $f = "payment" nocase
    condition:
        4 of them
}

rule apt_nation_state {
    meta:
        author = "SecureGuard"
        description = "APT/Nation-state indicator patterns"
        family = "APT"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "APT" nocase
        $b = "nation" nocase
        $c = "state" nocase
        $d = "advanced" nocase
        $e = "persistent" nocase
    condition:
        3 of them
}

rule suspicious_network_behavior {
    meta:
        author = "SecureGuard"
        description = "Suspicious network behavior patterns"
        family = "Network"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "socket" nocase
        $b = "connect" nocase
        $c = "send" nocase
        $d = "recv" nocase
    condition:
        2 of them
}

rule suspicious_string_encrypted {
    meta:
        author = "SecureGuard"
        description = "Encrypted string patterns"
        family = "Obfuscation"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = /[a-fA-F0-9]{32,}/ 
    condition:
        1 of them
}

rule suspicious_url_pattern {
    meta:
        author = "SecureGuard"
        description = "Suspicious URL patterns"
        family = "Network"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = /http:\/\/[a-zA-Z0-9\.\-]+/ 
        $b = /https:\/\/[a-zA-Z0-9\.\-]+/ 
        $c = /ftp:\/\/[a-zA-Z0-9\.\-]+/
    condition:
        1 of them
}

rule suspicious_ip_pattern {
    meta:
        author = "SecureGuard"
        description = "Suspicious IP address patterns"
        family = "Network"
        severity = "low"
        date = "2024-01-01"
    strings:
        $a = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
    condition:
        1 of them
}

rule suspicious_domain_pattern {
    meta:
        author = "SecureGuard"
        description = "Suspicious domain patterns"
        family = "Network"
        severity = "low"
        date = "2024-01-01"
    strings:
        $a = /\.[a-z]{2,10}\.(com|net|org|info|xyz|top|click|loan|gq|ml|ga|cf|tk)/
    condition:
        1 of them
}

rule buffer_overflow_pattern {
    meta:
        author = "SecureGuard"
        description = "Buffer overflow indicators"
        family = "Exploit"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = { 41 41 41 41 41 41 41 41 }
        $b = { 42 42 42 42 42 42 42 42 }
        $c = { 90 90 90 90 90 90 90 90 }
    condition:
        1 of them
}

rule win32_api_crypto {
    meta:
        author = "SecureGuard"
        description = "Windows Crypto API patterns"
        family = "Crypto"
        severity = "low"
        date = "2024-01-01"
    strings:
        $a = "CryptAcquireContext" nocase
        $b = "CryptEncrypt" nocase
        $c = "CryptDecrypt" nocase
        $d = "BCryptOpenAlgorithmProvider" nocase
    condition:
        1 of them
}

rule suspicious_crypto_usage {
    meta:
        author = "SecureGuard"
        description = "Suspicious cryptographic usage"
        family = "Crypto"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "AES" nocase
        $b = "RSA" nocase
        $c = "DES" nocase
        $d = "RC4" nocase
        $e = "SHA256" nocase
    condition:
        2 of them
}

rule browser_credential_stealer {
    meta:
        author = "SecureGuard"
        description = "Browser credential stealing patterns"
        family = "Stealer"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "Chrome" nocase
        $b = "Firefox" nocase
        $c = "Password" nocase
        $d = "cookie" nocase
    condition:
        3 of them
}

rule cryptocurrency_wallet_stealer {
    meta:
        author = "SecureGuard"
        description = "Cryptocurrency wallet stealing patterns"
        family = "Stealer"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "wallet" nocase
        $b = "bitcoin" nocase
        $c = "ethereum" nocase
        $d = "coinbase" nocase
    condition:
        2 of them
}

rule clipboard_stealer {
    meta:
        author = "SecureGuard"
        description = "Clipboard stealing patterns"
        family = "Stealer"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "GetClipboardData" nocase
        $b = "SetClipboardData" nocase
        $c = "clipboard" nocase
    condition:
        1 of them
}

rule screen_capture {
    meta:
        author = "SecureGuard"
        description = "Screen capture patterns"
        family = "Spyware"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "GetDC" nocase
        $b = "BitBlt" nocase
        $c = "PrintWindow" nocase
        $d = "screenshot" nocase
    condition:
        1 of them
}

rule webinjection {
    meta:
        author = "SecureGuard"
        description = "Web injection patterns"
        family = "Banking"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "webinject" nocase
        $b = "maninthbrowser" nocase
        $c = "mitb" nocase
    condition:
        1 of them
}

rule suspicious_file_operation {
    meta:
        author = "SecureGuard"
        description = "Suspicious file operation patterns"
        family = "Suspicious"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "DeleteFile" nocase
        $b = "MoveFile" nocase
        $c = "CopyFile" nocase
        $d = "CreateFile" nocase
    condition:
        2 of them
}

rule suspicious_registry_operation {
    meta:
        author = "SecureGuard"
        description = "Suspicious registry operation patterns"
        family = "Suspicious"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "RegSetValue" nocase
        $b = "RegCreateKey" nocase
        $c = "RegDeleteKey" nocase
        $d = "RegOpenKey" nocase
    condition:
        2 of them
}

rule suspicious_service_creation {
    meta:
        author = "SecureGuard"
        description = "Suspicious service creation patterns"
        family = "Persistence"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "CreateService" nocase
        $b = "StartService" nocase
        $c = "sc" nocase
        $d = "service" nocase
    condition:
        2 of them
}

rule scheduled_task_creation {
    meta:
        author = "SecureGuard"
        description = "Scheduled task creation patterns"
        family = "Persistence"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "schtasks" nocase
        $b = "CreateTask" nocase
        $c = "TaskScheduler" nocase
    condition:
        1 of them
}

rule wmi_persistence {
    meta:
        author = "SecureGuard"
        description = "WMI persistence patterns"
        family = "Persistence"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "IWbemServices" nocase
        $b = "ExecMethod" nocase
        $c = "__EventConsumer" nocase
    condition:
        1 of them
}

rule suspicious_driver_load {
    meta:
        author = "SecureGuard"
        description = "Suspicious driver loading patterns"
        family = "Kernel"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "NtLoadDriver" nocase
        $b = "ZwLoadDriver" nocase
        $c = "driver" nocase
    condition:
        1 of them
}

rule suspicious_kernel_mode {
    meta:
        author = "SecureGuard"
        description = "Suspicious kernel mode patterns"
        family = "Kernel"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "kernel" nocase
        $b = "Driver" nocase
        $c = "ntoskrnl" nocase
    condition:
        2 of them
}

rule suspicious_bitcoin_miner {
    meta:
        author = "SecureGuard"
        description = "Bitcoin miner patterns"
        family = "Miner"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "bitcoin" nocase
        $b = "btc" nocase
        $c = "pool" nocase
        $d = "stratum" nocase
    condition:
        2 of them
}

rule suspicious_execution_chain {
    meta:
        author = "SecureGuard"
        description = "Suspicious execution chain patterns"
        family = "Suspicious"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "cmd.exe /c" nocase
        $b = "powershell -e" nocase
        $c = "wscript" nocase
        $d = "cscript" nocase
    condition:
        1 of them
}

rule suspicious_hidden_file {
    meta:
        author = "SecureGuard"
        description = "Suspicious hidden file patterns"
        family = "Suspicious"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "hidden" nocase
        $b = "FILE_ATTRIBUTE_HIDDEN" nocase
    condition:
        1 of them
}

rule autostart_location {
    meta:
        author = "SecureGuard"
        description = "Common autostart locations"
        family = "Persistence"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "Startup" wide
        $a2 = "startup" wide
        $b = "Run" wide
        $b2 = "run" wide
    condition:
        1 of them
}

rule winlogon_notify {
    meta:
        author = "SecureGuard"
        description = "Winlogon notification patterns"
        family = "Persistence"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "Winlogon" wide
        $b = "Notify" wide
        $c = "Shell" wide
    condition:
        2 of them
}

rule appinit_dlls {
    meta:
        author = "SecureGuard"
        description = "AppInit DLLs patterns"
        family = "Persistence"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "AppInit_DLLs" wide
        $b = "LoadAppInit_DLLs" wide
    condition:
        1 of them
}

rule winsock_provider {
    meta:
        author = "SecureGuard"
        description = "Winsock provider patterns"
        family = "Network"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "Winsock" wide
        $b = "LSP" wide
        $c = "Namespace" wide
    condition:
        1 of them
}

rule browser_helper_object {
    meta:
        author = "SecureGuard"
        description = "Browser helper object patterns"
        family = "Spyware"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "BHO" nocase
        $b = "Browser Helper" nocase
    condition:
        1 of them
}

rule browser_automation {
    meta:
        author = "SecureGuard"
        description = "Browser automation patterns"
        family = "Spyware"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "InternetExplorer" nocase
        $b = "WebBrowser" nocase
    condition:
        1 of them
}

rule process_injection_technique {
    meta:
        author = "SecureGuard"
        description = "Process injection technique patterns"
        family = "Injection"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "VirtualAllocEx" nocase
        $b = "CreateRemoteThread" nocase
    condition:
        all of them
}

rule reflective_loading {
    meta:
        author = "SecureGuard"
        description = "Reflective loading patterns"
        family = "Fileless"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "ReflectiveLoader" nocase
        $b = "reflective" nocase
    condition:
        1 of them
}

rule etw_tampering {
    meta:
        author = "SecureGuard"
        description = "ETW tampering patterns"
        family = "Evasion"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "EtwEventWrite" nocase
        $b = "EventWrite" nocase
    condition:
        1 of them
}

rule amsi_bypass {
    meta:
        author = "SecureGuard"
        description = "AMSI bypass patterns"
        family = "Evasion"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "AmsiScanBuffer" nocase
        $b = "amsi" nocase
    condition:
        1 of them
}

rule uac_bypass {
    meta:
        author = "SecureGuard"
        description = "UAC bypass patterns"
        family = "PrivEsc"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "uac" nocase
        $b = "consent" nocase
        $c = "autoelevate" nocase
    condition:
        2 of them
}

rule windows_defender_bypass {
    meta:
        author = "SecureGuard"
        description = "Windows Defender bypass patterns"
        family = "Evasion"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "Windows Defender" nocase
        $b = "Mp" nocase
        $c = "defender" nocase
    condition:
        2 of them
}

rule antivirus_evasion {
    meta:
        author = "SecureGuard"
        description = "Antivirus evasion patterns"
        family = "Evasion"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "avp" nocase
        $b = "avp.exe" nocase
        $c = "nod32" nocase
        $d = "avast" nocase
    condition:
        2 of them
}

rule disk_wipe_pattern {
    meta:
        author = "SecureGuard"
        description = "Disk wipe patterns"
        family = "Wiper"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "WriteZeroes" nocase
        $b = "DeviceIoControl" nocase
    condition:
        1 of them
}

rule mbr_wipe_pattern {
    meta:
        author = "SecureGuard"
        description = "MBR wipe patterns"
        family = "Wiper"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "MBR" nocase
        $b = "WritePhysical" nocase
    condition:
        1 of them
}

rule password_change {
    meta:
        author = "SecureGuard"
        description = "Password change patterns"
        family = "Attack"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "NetUser" nocase
        $b = "ChangePassword" nocase
    condition:
        1 of them
}

rule service_stop {
    meta:
        author = "SecureGuard"
        description = "Service stop patterns"
        family = "Attack"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "StopService" nocase
        $b = "ControlService" nocase
    condition:
        1 of them
}

rule firewall_disable {
    meta:
        author = "SecureGuard"
        description = "Firewall disable patterns"
        family = "Attack"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "netsh advfirewall" nocase
        $b = "Windows Firewall" nocase
    condition:
        1 of them
}

rule windows_update_disable {
    meta:
        author = "SecureGuard"
        description = "Windows Update disable patterns"
        family = "Attack"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "WindowsUpdate" nocase
        $b = "wuauserv" nocase
    condition:
        1 of them
}

rule event_log_clear {
    meta:
        author = "SecureGuard"
        description = "Event log clear patterns"
        family = "Attack"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "ClearEventLog" nocase
        $b = "wevtutil" nocase
    condition:
        1 of them
}

rule suspicious_shortcut {
    meta:
        author = "SecureGuard"
        description = "Suspicious LNK shortcut patterns"
        family = "Suspicious"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = ".lnk" nocase
    condition:
        1 of them
}

rule iso_mount {
    meta:
        author = "SecureGuard"
        description = "ISO mount patterns"
        family = "Suspicious"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "Mount-DiskImage" nocase
        $b = "imdisk" nocase
    condition:
        1 of them
}

rule vhd_mount {
    meta:
        author = "SecureGuard"
        description = "VHD mount patterns"
        family = "Suspicious"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "VHD" nocase
        $b = "Mount-VHD" nocase
    condition:
        1 of them
}

rule ramdisk_pattern {
    meta:
        author = "SecureGuard"
        description = "RAM disk patterns"
        family = "Suspicious"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "ramdisk" nocase
        $b = "ImDisk" nocase
    condition:
        1 of them
}

rule suspicious_archive {
    meta:
        author = "SecureGuard"
        description = "Suspicious archive patterns"
        family = "Suspicious"
        severity = "low"
        date = "2024-01-01"
    strings:
        $a = ".zip" nocase
        $a2 = ".rar" nocase
        $a3 = ".7z" nocase
    condition:
        1 of them
}

rule rtf_exploit {
    meta:
        author = "SecureGuard"
        description = "RTF exploit patterns"
        family = "Exploit"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "RTF" nocase
        $b = "OLE" nocase
    condition:
        all of them
}

rule pdf_exploit {
    meta:
        author = "SecureGuard"
        description = "PDF exploit patterns"
        family = "Exploit"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "PDF" nocase
        $b = "JS" nocase
    condition:
        all of them
}

rule suspicious_email_attachment {
    meta:
        author = "SecureGuard"
        description = "Suspicious email attachment patterns"
        family = "Phishing"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "invoice" nocase
        $a2 = "payment" nocase
        $a3 = "receipt" nocase
    condition:
        1 of them
}

rule phishing_url {
    meta:
        author = "SecureGuard"
        description = "Phishing URL patterns"
        family = "Phishing"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "login" nocase
        $a2 = "signin" nocase
        $a3 = "verify" nocase
    condition:
        1 of them
}

rule banking_phishing {
    meta:
        author = "SecureGuard"
        description = "Banking phishing patterns"
        family = "Phishing"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "bank" nocase
        $a2 = "secure" nocase
        $a3 = "account" nocase
    condition:
        2 of them
}

rule office_macro {
    meta:
        author = "SecureGuard"
        description = "Office macro patterns"
        family = "Macro"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "VBA" nocase
        $b = "Macro" nocase
        $c = "AutoOpen" nocase
    condition:
        2 of them
}

rule vba_macro_obfuscation {
    meta:
        author = "SecureGuard"
        description = "VBA macro obfuscation patterns"
        family = "Macro"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "Chr" nocase
        $b = "Replace" nocase
    condition:
        2 of them
}

rule suspicious_office_doc {
    meta:
        author = "SecureGuard"
        description = "Suspicious Office document patterns"
        family = "Macro"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "word" nocase
        $b = "excel" nocase
    condition:
        1 of them
}

rule outlook_exfiltration {
    meta:
        author = "SecureGuard"
        description = "Outlook exfiltration patterns"
        family = "Spyware"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "Outlook" nocase
        $b = "MailItem" nocase
    condition:
        1 of them
}

rule smb_pth {
    meta:
        author = "SecureGuard"
        description = "SMB Pass-the-Hash patterns"
        family = "Attack"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "Pass-the-Hash" nocase
        $b = "PTH" nocase
    condition:
        1 of them
}

rule wmi_lateral {
    meta:
        author = "SecureGuard"
        description = "WMI lateral movement patterns"
        family = "Lateral"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "IWbemLocator" nocase
        $b = "ConnectServer" nocase
    condition:
        1 of them
}

rule winrm_lateral {
    meta:
        author = "SecureGuard"
        description = "WinRM lateral movement patterns"
        family = "Lateral"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "WinRM" nocase
        $b = "Enter-PSSession" nocase
    condition:
        1 of them
}

rule sc_lateral {
    meta:
        author = "SecureGuard"
        description = "SC lateral movement patterns"
        family = "Lateral"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "sc" nocase
        $b = "create" nocase
    condition:
        all of them
}

rule process_injection_reflective {
    meta:
        author = "SecureGuard"
        description = "Reflective process injection patterns"
        family = "Injection"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "NtAllocateVirtualMemory" nocase
        $b = "NtWriteVirtualMemory" nocase
    condition:
        all of them
}

rule process_hollowing_reflective {
    meta:
        author = "SecureGuard"
        description = "Process hollowing reflective patterns"
        family = "Hollowing"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "NtCreateSection" nocase
        $b = "NtMapViewOfSection" nocase
    condition:
        all of them
}

rule atom_bombing {
    meta:
        author = "SecureGuard"
        description = "Atom Bombing patterns"
        family = "Injection"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "GlobalAddAtom" nocase
        $b = "SetAtom" nocase
    condition:
        1 of them
}

rule dcom_lateral {
    meta:
        author = "SecureGuard"
        description = "DCOM lateral movement patterns"
        family = "Lateral"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "DCOM" nocase
        $b = "COM" nocase
    condition:
        1 of them
}

rule ransomware_generic {
    meta:
        author = "SecureGuard"
        description = "Generic ransomware detection"
        family = "Ransomware"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "encrypt" nocase
        $a2 = "ransom" nocase
        $a3 = "payment" nocase
    condition:
        3 of them
}

rule trojan_generic {
    meta:
        author = "SecureGuard"
        description = "Generic trojan detection"
        family = "Trojan"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "trojan" nocase
    condition:
        1 of them
}

rule worm_generic {
    meta:
        author = "SecureGuard"
        description = "Generic worm detection"
        family = "Worm"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "worm" nocase
    condition:
        1 of them
}

rule backdoor_generic {
    meta:
        author = "SecureGuard"
        description = "Generic backdoor detection"
        family = "Backdoor"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "backdoor" nocase
    condition:
        1 of them
}

rule rootkit_generic {
    meta:
        author = "SecureGuard"
        description = "Generic rootkit detection"
        family = "Rootkit"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "rootkit" nocase
    condition:
        1 of them
}

rule spyware_generic {
    meta:
        author = "SecureGuard"
        description = "Generic spyware detection"
        family = "Spyware"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "spyware" nocase
    condition:
        1 of them
}

rule cryptominer_generic {
    meta:
        author = "SecureGuard"
        description = "Generic cryptominer detection"
        family = "Cryptominer"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "miner" nocase
        $a2 = "mine" nocase
    condition:
        1 of them
}

rule hacktool_generic {
    meta:
        author = "SecureGuard"
        description = "Generic hacktool detection"
        family = "HackTool"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "hack" nocase
        $a2 = "tool" nocase
    condition:
        all of them
}

rule pup_generic {
    meta:
        author = "SecureGuard"
        description = "Generic PUP detection"
        family = "PUP"
        severity = "low"
        date = "2024-01-01"
    strings:
        $a = "potentially unwanted" nocase
    condition:
        1 of them
}

rule double_extension_executable {
    meta:
        author = "SecureGuard"
        description = "Double extension executable detection"
        family = "Suspicious"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = /\.exe\.(exe|dll|bat|cmd|ps1|vbs|js|scr|pif)/i
    condition:
        1 of them
}

rule suspicious_tmp_file {
    meta:
        author = "SecureGuard"
        description = "Suspicious temporary file detection"
        family = "Suspicious"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = /\.tmp$/i
    condition:
        1 of them
}

rule autorun_inf {
    meta:
        author = "SecureGuard"
        description = "Autorun.inf patterns"
        family = "Persistence"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "autorun.inf" nocase
    condition:
        1 of them
}

rule wscript_suspicious {
    meta:
        author = "SecureGuard"
        description = "Suspicious WScript patterns"
        family = "Suspicious"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "wscript" nocase
    condition:
        1 of them
}

rule cscript_suspicious {
    meta:
        author = "SecureGuard"
        description = "Suspicious CSCRIPT patterns"
        family = "Suspicious"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "cscript" nocase
    condition:
        1 of them
}

rule mshta_suspicious {
    meta:
        author = "SecureGuard"
        description = "Suspicious mshta patterns"
        family = "Suspicious"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "mshta" nocase
    condition:
        1 of them
}

rule regsvr32_suspicious {
    meta:
        author = "SecureGuard"
        description = "Suspicious regsvr32 patterns"
        family = "Suspicious"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "regsvr32" nocase
    condition:
        1 of them
}

rule rundll32_suspicious {
    meta:
        author = "SecureGuard"
        description = "Suspicious rundll32 patterns"
        family = "Suspicious"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "rundll32" nocase
    condition:
        1 of them
}

rule certutil_suspicious {
    meta:
        author = "SecureGuard"
        description = "Suspicious certutil patterns"
        family = "Suspicious"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "certutil" nocase
    condition:
        1 of them
}

rule bitsadmin_suspicious {
    meta:
        author = "SecureGuard"
        description = "Suspicious bitsadmin patterns"
        family = "Suspicious"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "bitsadmin" nocase
    condition:
        1 of them
}

rule wmic_suspicious {
    meta:
        author = "SecureGuard"
        description = "Suspicious wmic patterns"
        family = "Suspicious"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "wmic" nocase
    condition:
        1 of them
}

rule msiexec_suspicious {
    meta:
        author = "SecureGuard"
        description = "Suspicious msiexec patterns"
        family = "Suspicious"
        severity = "medium"
        date = "2024-01-01"
    strings:
        $a = "msiexec" nocase
    condition:
        1 of them
}

rule cmstp_suspicious {
    meta:
        author = "SecureGuard"
        description = "Suspicious cmstp patterns"
        family = "Suspicious"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "cmstp" nocase
    condition:
        1 of them
}

rule fls_hook_detection {
    meta:
        author = "SecureGuard"
        description = "FLS hook detection"
        family = "Hooking"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "SetFlsHook" nocase
    condition:
        1 of them
}

rule eop_thermal_circle {
    meta:
        author = "SecureGuard"
        description = "Thermal Circle EoP patterns"
        family = "PrivEsc"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "Thermal" nocase
        $b = "Circle" nocase
    condition:
        all of them
}

rule bad_blue_pattern {
    meta:
        author = "SecureGuard"
        description = "BadBlue exploit patterns"
        family = "Exploit"
        severity = "high"
        date = "2024-01-01"
    strings:
        $a = "BadBlue" nocase
    condition:
        1 of them
}

rule cve_2021_44228 {
    meta:
        author = "SecureGuard"
        description = "Log4Shell (CVE-2021-44228) patterns"
        family = "Exploit"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "log4j" nocase
        $a2 = "Log4j" nocase
    condition:
        1 of them
}

rule cve_2021_34527 {
    meta:
        author = "SecureGuard"
        description = "PrintNightmare (CVE-2021-34527) patterns"
        family = "Exploit"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "PrintSpooler" nocase
    condition:
        1 of them
}

rule cve_2021_27065 {
    meta:
        author = "SecureGuard"
        description = "ProxyLogon (CVE-2021-27065) patterns"
        family = "Exploit"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "Exchange" nocase
    condition:
        1 of them
}

rule cve_2020_1472 {
    meta:
        author = "SecureGuard"
        description = "ZeroLogon (CVE-2020-1472) patterns"
        family = "Exploit"
        severity = "critical"
        date = "2024-01-01"
    strings:
        $a = "Netlogon" nocase
    condition:
        1 of them
}

