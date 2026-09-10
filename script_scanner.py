"""
script_scanner.py
──────────────────────────────────────────────────────────────────────────
Fast, static, text-pattern scanner used by approval_bot.py to auto-clear
obviously-benign free-tier uploads and flag scripts that look like they
implement network abuse, malicious payloads, reverse shells, obfuscation,
or unauthorized system access.

Important limits, by design:
  - Ye file ko execute nahi karta, sirf text padhta hai (static analysis only).
  - Fast first-pass filter hai — known/obvious malicious patterns ko catch
    karta hai, ye guarantee nahi deta ki koi obfuscated/novel payload miss
    nahi hoga (e.g. string-splitting, alternate encodings, dynamic
    getattr() tricks can all evade plain regex matching). Isliye ye
    sandboxed execution (resource/network limits per run) ka replacement
    nahi hai, sirf ek additional layer hai.
"""
import re
from pathlib import Path

# (pattern, short category label, severity)
SUSPICIOUS_PATTERNS = [
    # Network Abuse & DoS
    (r'\bhping3\b', 'packet-flood tooling', 'high'),
    (r'\bmasscan\b', 'mass network scanning tooling', 'high'),
    (r'\bnmap\b[^\n]{0,40}-p\s*0-65535', 'mass port scanning', 'high'),
    (r'\bslowloris\b', 'DoS pattern', 'high'),
    (r'\bLOIC\b|\bHOIC\b', 'known DDoS tool reference', 'high'),
    (r'SYN[_ -]?flood|UDP[_ -]?flood|ICMP[_ -]?flood', 'flood-attack pattern', 'high'),
    (r'\bscapy\b[\s\S]{0,60}(send|sr1|flood)', 'raw packet crafting/flood', 'high'),
    (r'\bsocket\.SOCK_RAW\b', 'raw socket usage', 'medium'),
    
    # Brute-force & Exploits
    (r'\bhydra\b|\bmedusa\b|\bncrack\b', 'credential brute-force tooling', 'high'),
    (r'\bsqlmap\b', 'SQL-injection exploitation tooling', 'high'),
    (r'while\s+True\s*:[\s\S]{0,80}requests\.(get|post)', 'unbounded HTTP flood loop', 'medium'),
    
    # Reverse Shells & Remote Access (New Additions for High Security)
    (r'subprocess\.Popen\([^\n]*\b(nc|netcat|bash|sh|cmd\.exe|powershell)\b', 'reverse shell execution pattern', 'high'),
    (r'socket\.[Ss]ocket\([\s\S]{0,100}\.connect\([^\n]*(subprocess|os\.dup2|pty\.spawn)', 'interactive reverse shell', 'high'),
    (r'\b(exec|eval)\s*\(\s*(base64|bz2|zlib|codecs)\b', 'obfuscated/encoded payload execution', 'high'),
    (r'\bimport\s+pty\b[\s\S]{0,50}pty\.spawn', 'pty spawn for remote shell', 'high'),
    (r'(/bin/sh|/bin/bash|cmd\.exe)\b[^\n]{0,30}-i\b', 'interactive shell redirection', 'high'),

    # Cryptomining & Botnets
    (r'\bxmrig\b|stratum\+tcp://|\bcryptonight\b', 'crypto-mining indicators', 'high'),
    (r'/etc/shadow|/etc/passwd', 'sensitive host file access', 'medium'),
    (r'\bparamiko\b', 'SSH client library usage', 'medium'),
    (r'\btelnetlib\b|\btelnetlib3\b', 'raw telnet client usage', 'medium'),
    (r'\bbotnet\b|\bC2[_ -]?server\b|command[_ -]?and[_ -]?control', 'botnet/C2 terminology', 'medium'),
    (r'\bmirai\b|\bgafgyt\b|\bqbot\b', 'known IoT-botnet family reference', 'high'),

    # Destructive System Commands
    (r'rm\s+-rf\s+/(?!\S)', 'destructive filesystem wipe', 'high'),
    (r'os\.system\([^\n]*mkfs', 'disk formatting command', 'high'),
    (r'\bshodan\b|\bcensys\b|\bzoomeye\b', 'internet-wide host search API usage', 'medium'),
    
    # Credential Harvesting & Exfiltration
    (r'(wordlist|combolist|userlist|passlist|creds?_list)\s*=', 'bulk credential-list usage', 'medium'),
    (r"(admin|root)['\"]?\s*[,:]\s*['\"](admin|root|password|toor|12345)", 'default-credential list', 'medium'),
    (r'ip_network\([\s\S]{0,200}(socket\.connect|\.connect_ex|paramiko|telnetlib)', 'IP-range iteration + connection attempt', 'high'),
    (r'for\s+\w+\s+in\s+range\([\s\S]{0,120}\)\s*:[\s\S]{0,200}socket\.connect', 'ranged loop + raw socket connect', 'medium'),
    (r'ThreadPoolExecutor[\s\S]{0,150}(socket\.connect|paramiko|telnetlib)', 'multi-threaded mass connection attempts', 'high'),
    (r'(Path\(\s*[\'"]/[\'"]\s*\)|os\.walk\(\s*[\'"]/[\'"]\s*\))', 'recursive scan starting at filesystem root', 'high'),
    (r'id_rsa[\s\S]{0,200}authorized_keys|authorized_keys[\s\S]{0,200}id_rsa', 'SSH key/credential harvesting', 'high'),
    (r'-----BEGIN[^\n]{0,20}PRIVATE KEY-----', 'private-key content or private-key search pattern', 'high'),
    (r'\bAKIA[0-9A-Z]{16}\b|\bghp_[A-Za-z0-9]{20,}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}\b|\bsk_live_[A-Za-z0-9]{20,}\b', 'cloud/service credential value detected', 'high'),
    (r'(sendDocument|discord\.com/api/webhooks)[\s\S]{0,300}(zipfile|zipf\.write|rglob|os\.walk)', 'bulk file exfiltration to external chat/webhook', 'high'),
    (r'\bexfil(trat|_dir|_targets)\b', 'exfiltration-labeled code', 'high'),

    # Anti-Analysis & Evasion Patterns (New Additions)
    (r'ctypes\.windll|ptrace\(', 'anti-debugging/sandbox evasion technique', 'high'),
    (r'\bsys\.settrace\b', 'runtime trace-hooking (also used by legit profilers/coverage tools)', 'medium'),
    (r'urllib\.request\.urlopen\([^\n]*raw\.githubusercontent\.com[^\n]*\.(exe|sh|py|elf)', 'remote dropper script pattern', 'high'),

    # Large embedded blobs — a common way keyword-based patterns above get
    # bypassed (e.g. base64-encoding a payload so 'exec'/'nc'/etc. never
    # appear as literal text). This doesn't decode anything, it just flags
    # that an unusually long opaque string is present so a human/admin can
    # take a second look.
    (r'[A-Za-z0-9+/]{300,}={0,2}', 'large embedded base64-like blob', 'medium'),
]

MAX_SCAN_BYTES = 2_000_000  # 2MB tak ki limit taaki bade files system ko choke na karein


def scan_file(path: Path):
    """
    Returns (verdict, findings):
      verdict   'clear' | 'flagged'
      findings  list of (category_label, severity) tuples that matched

    Verdict logic: Agar koi bhi 'high' severity hit milta hai, ya 2 ya usse zyada 
    total hits milte hain, toh script automatically reject/flag ho jayegi.
    """
    path = Path(path)
    try:
        raw = path.read_bytes()[:MAX_SCAN_BYTES]
        text = raw.decode('utf-8', errors='ignore')
    except Exception:
        return 'clear', []

    findings = []
    for pattern, label, severity in SUSPICIOUS_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append((label, severity))

    has_high = any(sev == 'high' for _, sev in findings)
    verdict = 'flagged' if has_high or len(findings) >= 2 else 'clear'
    return verdict, findings
