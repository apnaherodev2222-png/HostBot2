"""Defensive static scanner for uploaded scripts. Never executes uploaded code."""
from __future__ import annotations
import ast
import re
from pathlib import Path
from typing import List, Tuple

Finding = Tuple[str, str]

SUSPICIOUS_PATTERNS = [
    (r"\bhping3\b", "packet-flood tooling", "high"),
    (r"\bmasscan\b", "mass network scanning tooling", "high"),
    (r"\bnmap\b[^\n]{0,80}(?:-p\s*0-65535|-p\s*1-65535)", "mass port scanning", "high"),
    (r"\bslowloris\b", "DoS pattern", "high"),
    (r"\b(?:LOIC|HOIC)\b", "known DDoS tool reference", "high"),
    (r"\b(?:SYN|UDP|ICMP)[ _-]?flood\b", "flood-attack pattern", "high"),
    (r"\bscapy\b[\s\S]{0,120}\b(?:send|sendp|sr1|srp|flood)\b", "raw packet crafting/flood", "high"),
    (r"\bsocket\.SOCK_RAW\b", "raw socket usage", "medium"),
    (r"\b(?:hydra|medusa|ncrack)\b", "credential brute-force tooling", "high"),
    (r"\bsqlmap\b", "SQL-injection exploitation tooling", "high"),
    (r"while\s+True\s*:[\s\S]{0,160}\brequests\.(?:get|post|put|delete)\b", "unbounded HTTP request loop", "medium"),
    (r"subprocess\.(?:Popen|run|call|check_output)\([\s\S]{0,220}\b(?:nc|netcat|bash|sh|cmd\.exe|powershell)\b", "remote shell execution pattern", "high"),
    (r"\bsocket\.socket\([\s\S]{0,180}\.connect\([\s\S]{0,180}(?:subprocess|os\.dup2|pty\.spawn)", "interactive reverse shell", "high"),
    (r"\b(?:exec|eval)\s*\(\s*(?:base64|bz2|zlib|codecs)\b", "obfuscated/encoded payload execution", "high"),
    (r"\bimport\s+pty\b[\s\S]{0,100}\bpty\.spawn\b", "pty spawn for remote shell", "high"),
    (r"(?:/bin/sh|/bin/bash|cmd\.exe)\b[^\n]{0,50}-i\b", "interactive shell redirection", "high"),
    (r"\bxmrig\b|stratum\+tcp://|\bcryptonight\b", "crypto-mining indicator", "high"),
    (r"/etc/(?:shadow|passwd)\b", "sensitive host file access", "medium"),
    (r"\bparamiko\b", "SSH client library usage", "medium"),
    (r"\btelnetlib(?:3)?\b", "raw telnet client usage", "medium"),
    (r"\b(?:botnet|C2[_ -]?server|command[_ -]?and[_ -]?control)\b", "botnet/C2 terminology", "medium"),
    (r"\b(?:mirai|gafgyt|qbot)\b", "known IoT-botnet family reference", "high"),
    (r"\brm\s+-rf\s+/(?:\s|['\"]|$)", "destructive filesystem wipe", "high"),
    (r"os\.system\([\s\S]{0,120}\bmkfs(?:\b|\.)", "disk formatting command", "high"),
    (r"\b(?:shodan|censys|zoomeye)\b", "internet-wide host search API usage", "medium"),
    (r"(?:wordlist|combolist|userlist|passlist|creds?_list)\s*=", "bulk credential-list usage", "medium"),
    (r"(?:admin|root)['\"]?\s*[,:]\s*['\"](?:admin|root|password|toor|12345)", "default-credential list", "medium"),
    (r"\bip_network\([\s\S]{0,260}(?:socket\.connect|\.connect_ex|paramiko|telnetlib)", "IP-range iteration plus connection attempt", "high"),
    (r"for\s+\w+\s+in\s+range\([\s\S]{0,160}\)\s*:[\s\S]{0,260}socket\.connect", "ranged loop plus raw socket connect", "medium"),
    (r"ThreadPoolExecutor[\s\S]{0,220}(?:socket\.connect|paramiko|telnetlib)", "multi-threaded mass connection attempts", "high"),
    (r"(?:Path\(\s*['\"]\/['\"]\s*\)|os\.walk\(\s*['\"]\/['\"]\s*\))", "recursive scan starting at filesystem root", "high"),
    (r"id_rsa[\s\S]{0,220}authorized_keys|authorized_keys[\s\S]{0,220}id_rsa", "SSH key/credential harvesting", "high"),
    (r"-----BEGIN[^\n]{0,30}PRIVATE KEY-----", "private-key content or search pattern", "high"),
    (r"\bAKIA[0-9A-Z]{16}\b|\bghp_[A-Za-z0-9]{20,}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}\b|\bsk_live_[A-Za-z0-9]{20,}\b", "cloud/service credential value detected", "high"),
    (r"(?:sendDocument|discord\.com/api/webhooks)[\s\S]{0,350}(?:zipfile|zipf\.write|rglob|os\.walk)", "bulk file exfiltration to external chat/webhook", "high"),
    (r"\bexfil(?:trat|_dir|_targets)\b", "exfiltration-labeled code", "high"),
    (r"ctypes\.windll|ptrace\(", "anti-debugging/sandbox evasion technique", "high"),
    (r"\bsys\.settrace\b", "runtime trace-hooking", "medium"),
    (r"urllib\.request\.urlopen\([^\n]*raw\.githubusercontent\.com[^\n]*\.(?:exe|sh|py|elf)", "remote dropper script pattern", "high"),
]
SECRET_PATTERNS = [
    # Was "high" — but a simple bot hardcoding ITS OWN token is completely
    # normal (most beginner Telegram bots do this), so this alone
    # shouldn't trigger an instant flag+mute. "medium" means it only
    # matters combined with something else genuinely suspicious.
    (r"\b\d{8,12}:[A-Za-z0-9_-]{20,}\b", "Telegram-like bot token (normal for simple bots — only a real problem combined with other flags)", "medium"),
    (r"\bghp_[A-Za-z0-9]{20,}\b", "GitHub token", "high"),
    (r"\bsk_live_[A-Za-z0-9]{20,}\b", "Stripe secret key", "high"),
]
MAX_SCAN_BYTES = 2_000_000
MAX_FINDINGS = 50

# AST deep-scan (Python files only). Regex only sees TEXT — a pattern like
# `(exec|eval)\s*\(\s*(base64|bz2|zlib|codecs)\b` only matches when one of
# those names is the LITERAL first token; `import zlib as _zl` then
# `exec(compile(_zl.decompress(x)))` slides straight past it. This walks
# the actual syntax tree instead, so it catches "eval/exec called with a
# dynamically-computed argument" regardless of what the attacker names
# their variables or aliases their imports.
_SENSITIVE_DIRS = {"/", "/root", "/etc", "/home", "/proc", "/var", "/sys"}
_SUSPICIOUS_CLASS_WORDS = {"harvest", "steal", "exfil", "harvester", "collector", "grabber"}

def _ast_findings(text: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return findings  # already recorded as "Python syntax error" by the caller
    except (ValueError, RecursionError):
        findings.append(("code structure too complex/malformed to analyze safely", "medium"))
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                if func.id in ("eval", "exec") and node.args:
                    arg0 = node.args[0]
                    if isinstance(arg0, (ast.Call, ast.Attribute, ast.BinOp)):
                        findings.append((f"{func.id}() called with a dynamically-computed argument — hidden/decoded code execution", "high"))
                if func.id == "__import__" and node.args:
                    arg0 = node.args[0]
                    if isinstance(arg0, ast.Constant) and arg0.value in ("os", "subprocess", "ctypes"):
                        findings.append((f"dynamic __import__('{arg0.value}') — avoids a plain import statement", "medium"))
            if isinstance(func, ast.Attribute):
                if (func.attr == "walk" and isinstance(func.value, ast.Name)
                        and func.value.id == "os" and node.args):
                    arg0 = node.args[0]
                    if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str) and arg0.value in _SENSITIVE_DIRS:
                        findings.append((f"os.walk('{arg0.value}') — scanning a system directory, not its own folder", "high"))
        if isinstance(node, ast.ClassDef):
            name_lower = node.name.lower()
            if any(w in name_lower for w in _SUSPICIOUS_CLASS_WORDS):
                findings.append((f"class name '{node.name}' suggests data harvesting/exfiltration", "medium"))
    return findings

def _dedupe(findings: List[Finding]) -> List[Finding]:
    return list(dict.fromkeys(findings))[:MAX_FINDINGS]

def scan_file(path: Path):
    path = Path(path)
    try:
        if not path.is_file():
            return "flagged", [("uploaded path is not a regular file", "high")]
        file_size = path.stat().st_size
    except Exception as exc:
        return "flagged", [(f"scanner could not read file: {type(exc).__name__}", "high")]

    # Was: read_bytes()[:MAX_SCAN_BYTES] — silently truncated anything past
    # 2MB and scanned only the head, so padding a file past the cutoff and
    # putting the payload after it was a trivial bypass. Extremely large
    # files (40MB+) are flagged for manual review instead of being
    # partially scanned and waved through; anything more reasonable gets
    # scanned in full via overlapping chunks so a pattern straddling a
    # chunk boundary still matches.
    if file_size > MAX_SCAN_BYTES * 20:
        return "flagged", [(f"file too large to scan safely ({file_size} bytes) — sent for manual review", "high")]

    try:
        text = path.read_bytes().decode("utf-8", errors="ignore")
    except Exception as exc:
        return "flagged", [(f"scanner could not read file: {type(exc).__name__}", "high")]

    all_patterns = SUSPICIOUS_PATTERNS + SECRET_PATTERNS
    findings: List[Finding] = []
    seen_labels = set()
    overlap = 256
    pos = 0
    text_len = len(text)
    while pos < text_len:
        chunk = text[pos:pos + MAX_SCAN_BYTES]
        for pattern, label, severity in all_patterns:
            if label in seen_labels:
                continue
            try:
                if re.search(pattern, chunk, re.IGNORECASE):
                    findings.append((label, severity))
                    seen_labels.add(label)
            except re.error:
                continue
        pos += MAX_SCAN_BYTES - overlap

    if path.suffix.lower() == ".py":
        try:
            ast.parse(text, filename=str(path))
        except SyntaxError:
            findings.append(("Python syntax error", "medium"))
        else:
            for label, severity in _ast_findings(text):
                if label not in seen_labels:
                    findings.append((label, severity))
                    seen_labels.add(label)

    findings = _dedupe(findings)
    verdict = "flagged" if any(s == "high" for _, s in findings) or len(findings) >= 2 else "clear"
    return verdict, findings
