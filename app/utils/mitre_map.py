MITRE_KEYWORD_MAP = {
    # Privilege Escalation
    "privilege escalation": "T1068",
    "escalation of privilege": "T1068",

    # Execution Techniques
    "powershell": "T1086",
    "command injection": "T1059",
    "command execution": "T1059",
    "remote code execution": "T1203",
    "rce": "T1203",
    "script execution": "T1064",

    # Credential Access
    "credential dumping": "T1003",
    "password dumping": "T1003",
    "password spraying": "T1110",
    "brute force": "T1110",
    "credential stuffing": "T1110",

    # Web Application Attacks
    "sql injection": "T1190",
    "sqli": "T1190",
    "cross site scripting": "T1059.007",
    "xss": "T1059.007",
    "csrf": "T1184",
    "cross site request forgery": "T1184",
    "path traversal": "T1106",
    "file inclusion": "T1505.003",
    "local file inclusion": "T1505.003",
    "remote file inclusion": "T1505.003",
    "command injection": "T1059",
    "input validation": "T1592",  # Reconnaissance for input validation weaknesses

    # Malware / Malicious Software
    "malware": "T1204",
    "ransomware": "T1486",
    "trojan": "T1204",
    "backdoor": "T1071.001",
    "botnet": "T1090",
    "rootkit": "T1014",
    "virus": "T1204",

    # Lateral Movement & Network
    "lateral movement": "T1021",
    "remote desktop": "T1076",
    "remote desktop protocol": "T1076",
    "pass the hash": "T1075",
    "pass-the-ticket": "T1550.003",
    "internal spear phishing": "T1566.001",

    # Data Exfiltration & Impact
    "data exfiltration": "T1041",
    "data theft": "T1041",
    "data leakage": "T1537",
    "denial of service": "T1499",
    "dos": "T1499",
    "distributed denial of service": "T1499",
    "ddos": "T1499",

    # Persistence
    "registry run keys": "T1547.001",
    "service creation": "T1543",
    "scheduled task": "T1053",
    "startup folder": "T1547.002",

    # Defense Evasion
    "code injection": "T1055",
    "process hollowing": "T1055.012",
    "file deletion": "T1107",
    "obfuscated files": "T1027",
    "anti virus": "T1562",
    "anti sandbox": "T1562.001",
    "disable security tools": "T1562.001",

    # Reconnaissance
    "network scanning": "T1046",
    "port scanning": "T1046",
    "whois": "T1590",
    "os fingerprinting": "T1590",

    # SSHD session corruption events → possible T1021.004 (Remote File Copy / SSH)
    "sshd corrupted bytes": {"id": "T1021.004"},
    "sshd insecure connection attempt": {"id": "T1021.004"},

    # Agent flooding rules
    "agent event queue is flooded": {"id": "T1071"},  # Exfil via application layer protocol (example)
    "agent event queue is full": {"id": "T1071"},
    "agent buffer": {"id": "T1071"},

    # Buffer overflow attacks (on ftp/rpc)
    "buffer overflow": {"id": "T1055"},  # Process Injection example

    # Solaris/rpc overflow
    "heap overflow": {"id": "T1570"},  # Example technique, adjust as needed

    # Netscreen firewall multiple alerts
    "netscreen firewall multiple alert": "T1499",  # Endpoint Denial of Service

    # Microsoft Security Essentials AV warnings
    "microsoft security essentials av warning": "T1059",  # Command and Scripting Interpreter
    "virus detected but unable to remove": "T1059",

    # Fortigate attack detected
    "fortigate attack detected": "T1499",  # Endpoint Denial of Service

    # MS-DHCP lease request could not be satisfied
    "dhcp lease request could not be satisfied": "T1579",  # Network Service Scanning
    "dhcp scope full": "T1579",
    "rogue server detection": "T1579",

    # proftpd FTP process crashed
    "proftpd ftp process crashed": "T1499",  # Endpoint Denial of Service

    # Agent event queue flooded
    "agent event queue flooded": "T1499",

    # File monitoring limit exceeded
    "file limit set for this agent exceeded": "T1083",  # File and Directory Discovery



}
