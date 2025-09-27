"""auditor.py
Main CLI. Reads passwords (argument, input-file or interactive), runs checks and generates a Markdown report.
"""
import argparse
from pathlib import Path
from rich.console import Console
from utils import estimate_entropy, contains_common_pattern

console = Console()

COMMON_WORDLIST = Path("wordlists/common_passwords.txt")

def load_wordlist(path: Path):
    if not path.exists():
        return set()
    return {line.strip() for line in path.read_text(encoding="utf8").splitlines() if line.strip()}

def analyze_password(pw: str, wordlist: set):
    ent = estimate_entropy(pw)
    checks = {
        "length": len(pw),
        "entropy_bits": round(ent, 2),
        "is_common": pw.lower() in wordlist,
        "common_pattern": contains_common_pattern(pw),
        "has_upper": any(c.isupper() for c in pw),
        "has_lower": any(c.islower() for c in pw),
        "has_digit": any(c.isdigit() for c in pw),
        "has_symbol": any(not c.isalnum() for c in pw),
    }
    recommendations = []
    if checks["length"] < 8:
        recommendations.append("Increase length to at least 12 characters.")
    if ent < 40:
        recommendations.append("Increase character diversity to raise entropy.")
    if checks["is_common"]:
        recommendations.append("Do not use common passwords.")

    return {"password": pw, **checks, "recommendations": recommendations}

def format_report(entries: list) -> str:
    lines = ["# Password Audit Report\n"]
    for i, e in enumerate(entries, 1):
        lines.append(f"## Entry {i}\n")
        masked = e['password']
        if len(masked) > 4:
            masked_display = f"{masked[:2]}***{masked[-2:]}"
        elif len(masked) > 2:
            masked_display = f"{masked[0]}***{masked[-1]}"
        else:
            masked_display = "***"
        lines.append(f"- Password (masked): `{masked_display}`")
        lines.append(f"- Length: {e['length']}")
        lines.append(f"- Entropy (bits): {e['entropy_bits']}")
        lines.append(f"- In common wordlist: {e['is_common']}")
        if e.get('common_pattern'):
            lines.append(f"- Contains common pattern: True")
        for r in e['recommendations']:
            lines.append(f"- Recommendation: {r}")
        lines.append('\n')
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="Password Auditor — use only in a controlled lab environment")
    parser.add_argument("--password", type=str, help="Password to audit")
    parser.add_argument("--input-file", type=str, help="File with passwords, one per line")
    parser.add_argument("--output", type=str, help="Markdown output file")
    args = parser.parse_args()

    wordlist = load_wordlist(COMMON_WORDLIST)

    entries = []
    if args.password:
        entries.append(analyze_password(args.password, wordlist))
    elif args.input_file:
        p = Path(args.input_file)
        if not p.exists():
            console.print(f"[red]File not found: {args.input_file}")
            return
        for line in p.read_text(encoding="utf8").splitlines():
            if line.strip():
                entries.append(analyze_password(line.strip(), wordlist))
    else:
        console.print("Enter a password:")  # rich hides input only with getpass; simplified here
        pw = console.input("Password: ")
        entries.append(analyze_password(pw, wordlist))

    report = format_report(entries)
    if args.output:
        Path(args.output).write_text(report, encoding="utf8")
        console.print(f"Report saved to {args.output}")
    else:
        console.print(report)

if __name__ == '__main__':
    main()
