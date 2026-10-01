#!/usr/bin/env python3
"""
==============================================================================
PROJECT AEGIS: PRE-COMMIT SECURITY HOOK & DEVELOPER SECRET AUDITOR
Zero External Dependencies (Pure Python Standard Library)
Usage:
  python aegis.py             # Pre-commit staged diff inspection
  python aegis.py --fix       # Auto-extract leaked secrets to .env
==============================================================================
"""

import sys
import os
import re
import math
import json
import argparse
import subprocess
import urllib.request
import urllib.error

# ANSI Cyber-Luxe Color Codes
CYAN = "\033[96m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Core Local Signatures (Offline Fallback Engine)
LOCAL_PATTERNS = [
    (r"\b(AKIA[0-9A-Z]{16})\b", "AWS Access Key ID"),
    (r"\b(AIza[0-9A-Za-z\-_]{35})\b", "Google Cloud / Gemini Key"),
    (r"\b(ghp_[0-9a-zA-Z]{36})\b", "GitHub Classic PAT"),
    (r"\b(github_pat_[0-9a-zA-Z_]{82})\b", "GitHub Fine-Grained Token"),
    (r"\b(sk-[a-zA-Z0-9]{48})\b", "OpenAI Secret Key"),
    (r"\b(sk-proj-[a-zA-Z0-9_\-]{48,128})\b", "OpenAI Project Key"),
    (r"\b(sk_(?:live|test)_[0-9a-zA-Z]{24,99})\b", "Stripe API Key"),
    (r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b", "Slack Token"),
    (r"(-----BEGIN (?:RSA )?PRIVATE KEY-----)", "RSA Private Key"),
]


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy in bits per character."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in set(data):
        p_x = float(data.count(x)) / length
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 3)


def redact_token(token: str) -> str:
    """Redacts central characters of exposed secrets."""
    if len(token) <= 8:
        return "********"
    masked_length = min(len(token) - 8, 20)
    return f"{token[:4]}{'*' * masked_length}{token[-4:]}"


def get_staged_diff() -> str:
    """Extracts git diff for all currently staged files."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--unified=0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"{RED}[Aegis Error] Failed to execute git diff: {e}{RESET}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"{RED}[Aegis Error] 'git' binary not found in system PATH.{RESET}")
        sys.exit(1)


def parse_staged_lines(diff_text: str):
    """Parses git unified diff to locate staged file names and added lines."""
    staged_items = []
    current_file = None

    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            code_line = line[1:]
            staged_items.append((current_file, code_line))
    return staged_items


def run_local_audit(staged_items):
    """Offline Heuristic & Shannon Entropy Audit."""
    findings = []
    for filename, code_line in staged_items:
        # Check explicit patterns
        for pattern, name in LOCAL_PATTERNS:
            matches = re.findall(pattern, code_line)
            for match in matches:
                findings.append({
                    "file": filename,
                    "name": name,
                    "raw": match,
                    "redacted": redact_token(match),
                    "entropy": calculate_shannon_entropy(match)
                })

        # Check raw high-entropy string literals
        tokens = re.findall(r"[A-Za-z0-9_\-+=]{18,80}", code_line)
        for token in tokens:
            entropy = calculate_shannon_entropy(token)
            if entropy > 3.9 and len(set(token)) >= 10:
                if not any(f["raw"] == token for f in findings):
                    findings.append({
                        "file": filename,
                        "name": "High-Entropy Secret Literal",
                        "raw": token,
                        "redacted": redact_token(token),
                        "entropy": entropy
                    })
    return findings


def run_cloud_audit(api_key: str, endpoint: str, diff_text: str):
    """Transmits staged diff to Project Aegis GitShield Server for verification."""
    url = f"{endpoint.rstrip('/')}/api/scan/secret"
    payload = json.dumps({
        "filename": "staged_commit_diff",
        "content": diff_text
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "AegisCli/1.0"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                if data.get("findingsCount", 0) > 0:
                    return data
    except urllib.error.HTTPError as e:
        print(f"{YELLOW}[Aegis Warning] Server audit returned HTTP {e.code}. Falling back to offline scan.{RESET}")
    except Exception as e:
        print(f"{YELLOW}[Aegis Warning] Cloud sync failed ({e}). Proceeding offline.{RESET}")
    return None


def apply_remediation(findings):
    """Extracts secrets to .env and replaces references in staged files."""
    if not findings:
        print(f"{GREEN}[Aegis] No secrets detected to remediate.{RESET}")
        return

    env_lines = []
    for i, finding in enumerate(findings):
        var_name = f"AEGIS_SECRET_{i+1}"
        env_lines.append(f"{var_name}=\"{finding['raw']}\"")

        # Replace in targeted file
        target_file = finding["file"]
        if target_file and os.path.exists(target_file):
            with open(target_file, "r", encoding="utf-8") as f:
                content = f.read()
            new_content = content.replace(finding["raw"], f"process.env.{var_name}")
            with open(target_file, "w", encoding="utf-8") as f:
                f.write(new_content)
            subprocess.run(["git", "add", target_file])
            print(f"{CYAN}-> Sanitized {target_file} (replaced with process.env.{var_name}){RESET}")

    # Append to .env
    with open(".env", "a", encoding="utf-8") as f:
        f.write("\n# Auto-remediated by Project Aegis\n" + "\n".join(env_lines) + "\n")
    print(f"{GREEN}-> Appended {len(env_lines)} extracted secret(s) to .env{RESET}")

    # Ensure .env is in .gitignore
    gitignore_path = ".gitignore"
    needs_ignore = True
    if os.path.exists(gitignore_path):
        with open(gitignore_path, "r", encoding="utf-8") as f:
            if ".env" in f.read():
                needs_ignore = False

    if needs_ignore:
        with open(gitignore_path, "a", encoding="utf-8") as f:
            f.write("\n.env\n.env.local\n")
        subprocess.run(["git", "add", gitignore_path])
        print(f"{GREEN}-> Appended .env protection to .gitignore and staged.{RESET}")


def print_banner():
    print(f"{CYAN}{BOLD}")
    print("+--------------------------------------------------------------+")
    print("|         PROJECT AEGIS - GITSHIELD COMMIT DEFENSE             |")
    print("+--------------------------------------------------------------+")
    print(f"{RESET}")


def main():
    parser = argparse.ArgumentParser(description="Project Aegis GitShield Pre-Commit Guard")
    parser.add_argument("--fix", action="store_true", help="Auto-remediate secrets to .env")
    parser.add_argument("--endpoint", default=os.getenv("AEGIS_ENDPOINT", "http://localhost:3000"))
    args = parser.parse_args()

    diff = get_staged_diff()
    if not diff.strip():
        sys.exit(0)

    staged_items = parse_staged_lines(diff)
    local_findings = run_local_audit(staged_items)

    api_key = os.getenv("AEGIS_API_KEY")
    server_findings = None
    if api_key:
        server_findings = run_cloud_audit(api_key, args.endpoint, diff)

    # Prioritize server report if available, else local
    total_findings = local_findings
    if server_findings and "findings" in server_findings:
        total_findings = [
            {
                "file": "staged_file",
                "name": f["name"],
                "raw": f.get("rawToken", ""),
                "redacted": f["redactedToken"],
                "entropy": f.get("entropy", 0.0)
            }
            for f in server_findings["findings"]
        ]

    if not total_findings:
        sys.exit(0)

    print_banner()
    print(f"{RED}{BOLD}COMMIT BLOCKED: Unencrypted developer secrets detected!{RESET}\n")

    for finding in total_findings:
        print(f"  * {BOLD}Target File:{RESET} {finding.get('file', 'unknown')}")
        print(f"    {YELLOW}Signature:{RESET}   {finding['name']}")
        print(f"    {CYAN}Token Redacted:{RESET} {finding['redacted']}")
        if finding.get("entropy"):
            print(f"    {CYAN}Entropy:{RESET}        {finding['entropy']} bits/char")
        print()

    if args.fix:
        print(f"{CYAN}Applying automatic GitShield remediation patch...{RESET}")
        apply_remediation(local_findings)
        print(f"\n{GREEN}{BOLD}Secrets extracted successfully. Re-run 'git commit' to complete.{RESET}\n")
        sys.exit(0)
    else:
        print(f"{YELLOW}Remediation options:{RESET}")
        print(f"  1. Run {BOLD}python aegis.py --fix{RESET} to extract secrets into .env automatically.")
        print(f"  2. Unstage changes manually: {BOLD}git reset HEAD <file>{RESET}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
