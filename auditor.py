"""auditor.py
Main CLI. Reads passwords (argument, input-file or interactive), runs checks,
generates a Markdown report and estimates crack times from entropy.
"""

# Author: lostWalle268 

import argparse
import math
from pathlib import Path
from rich.console import Console
from rich.table import Table
from utils import estimate_entropy, contains_common_pattern

console = Console()
COMMON_WORDLIST = Path("wordlists/common_passwords.txt")

# Attacker guess rates (guesses per second) for different realistic scenarios.
# These are illustrative values; real speeds depend on hash algorithm, salt, hardware.
ATTACKER_PROFILES = {
    "online_low": 10,              # e.g., online login attempts limited by throttling (10 guesses/sec)
    "online_high": 100,            # permissive online service or distributed attempts (100/s)
    "single_gpu": 10_000_000,      # single GPU, optimistic for fast hashing (1e7 guesses/sec)
    "gpu_rig": 1_000_000_000,      # multi-GPU rig (1e9 guesses/sec)
    "asic_farm": 10_000_000_000,   # massive specialized hardware (1e10 guesses/sec)
}

def load_wordlist(path: Path):
    if not path.exists():
        return set()
    return {line.strip().lower() for line in path.read_text(encoding="utf8").splitlines() if line.strip()}

# --- Crack time helpers ---------------------------------------------------
def seconds_to_readable(sec: float) -> str:
    """Convert seconds to a human readable string (years/days/hours/mins/secs)."""
    if sec == float("inf"):
        return "∞"
    if sec < 1:
        return f"{sec:.3f} s"
    # compute integer components
    s = int(sec)  # total seconds as integer
    # sec -> min
    MIN = 60
    HOUR = 60 * MIN
    DAY = 24 * HOUR
    YEAR = 365 * DAY

    years = s // YEAR
    s = s % YEAR
    days = s // DAY
    s = s % DAY
    hours = s // HOUR
    s = s % HOUR
    minutes = s // MIN
    seconds = s % MIN

    parts = []
    if years:
        parts.append(f"{years}y")
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if seconds or not parts:
        parts.append(f"{seconds}s")
    return " ".join(parts)

def estimate_crack_time_seconds(entropy_bits: float, guesses_per_second: float) -> float:
    """
    Estimate time (seconds) to exhaustively search 2^(entropy_bits) possibilities
    at guesses_per_second rate.

    Uses float math with pow(2, entropy_bits). Handles extreme values by returning inf.
    """
    try:
        # possibilities = 2 ** entropy_bits
        possibilities = math.pow(2.0, float(entropy_bits))
        if math.isinf(possibilities) or possibilities > 1e308:
            return float("inf")
        # time in seconds
        t = possibilities / float(guesses_per_second) if guesses_per_second > 0 else float("inf")
        return t
    except OverflowError:
        return float("inf")
    except Exception:
        return float("inf")

def estimate_crack_times(entropy_bits: float) -> dict:
    """
    Return a mapping profile_name -> (seconds, human_readable) for pre-defined attacker profiles.
    """
    results = {}
    for name, rate in ATTACKER_PROFILES.items():
        sec = estimate_crack_time_seconds(entropy_bits, rate)
        results[name] = {"seconds": sec, "display": seconds_to_readable(sec), "rate": rate}
    return results

# --- Password analysis ----------------------------------------------------
KEYBOARD_PATTERNS = ["qwerty", "asdf", "zxcv", "12345", "password", "admin", "letmein"]

def is_sequential(pw: str) -> bool:
    """Detect ascending or descending sequences like 'abcd' or '1234' (simple heuristic)."""
    seq = "abcdefghijklmnopqrstuvwxyz"
    num = "0123456789"
    pw_low = pw.lower()
    length = len(pw_low)
    for size in (4, 3):  # check chunks of length 4 and 3
        for i in range(length - size + 1):
            chunk = pw_low[i:i+size]
            if chunk in seq or chunk[::-1] in seq:  # forward or backward
                return True
            if chunk in num or chunk[::-1] in num:
                return True
    return False

def analyze_password(pw: str, wordlist: set):
    """Analyze a single password and return a dict with metrics, recommendations and crack times."""
    ent = estimate_entropy(pw)
    pw_lower = pw.lower()

    checks = {
        "length": len(pw),
        "entropy_bits": round(ent, 2),
        "is_common": pw_lower in wordlist,
        "common_pattern": contains_common_pattern(pw),
        "keyboard_pattern": any(pat in pw_lower for pat in KEYBOARD_PATTERNS),
        "sequential": is_sequential(pw),
        "has_upper": any(c.isupper() for c in pw),
        "has_lower": any(c.islower() for c in pw),
        "has_digit": any(c.isdigit() for c in pw),
        "has_symbol": any(not c.isalnum() for c in pw),
    }

    # Strength labeling
    if checks["length"] < 8 or checks["is_common"] or ent < 28:
        strength = "Weak"
    elif ent < 50:
        strength = "Medium"
    else:
        strength = "Strong"

    # Recommendations
    recommendations = []
    if checks["length"] < 12:
        recommendations.append("Increase length to at least 12 characters.")
    if ent < 40:
        recommendations.append("Increase character diversity to raise entropy (mix upper/lower/digits/symbols).")
    if checks["is_common"]:
        recommendations.append("Avoid common passwords (in wordlists).")
    if checks["keyboard_pattern"]:
        recommendations.append("Avoid keyboard patterns (e.g. 'qwerty', '12345').")
    if checks["sequential"]:
        recommendations.append("Avoid sequential characters (e.g. 'abcd', '1234').")
    if not checks["has_symbol"]:
        recommendations.append("Consider adding at least one symbol to improve strength.")

    # Crack time estimates for multiple attacker profiles
    crack = estimate_crack_times(ent)

    return {
        "password": pw,
        **checks,
        "strength": strength,
        "recommendations": recommendations,
        "crack_times": crack,
    }

# --- Reporting ------------------------------------------------------------
def format_crack_table(crack_times: dict) -> str:
    """Return a small Markdown table with attacker profile, rate and display time."""
    lines = []
    lines.append("| Profile | Rate (guesses/sec) | Estimated time to exhaust space |")
    lines.append("|---:|---:|---|")
    for profile, info in crack_times.items():
        rate = f"{info['rate']:,}"
        lines.append(f"| {profile} | {rate} | {info['display']} |")
    return "\n".join(lines)

def format_report(entries: list) -> str:
    lines = ["# Password Audit Report\n"]
    weak_count = 0

    for i, e in enumerate(entries, 1):
        lines.append(f"## Entry {i}\n")
        pw = e["password"]
        if len(pw) > 4:
            masked = f"{pw[:2]}***{pw[-2:]}"
        elif len(pw) > 2:
            masked = f"{pw[0]}***{pw[-1]}"
        else:
            masked = "***"

        lines.append(f"- Password (masked): `{masked}`")
        lines.append(f"- Length: {e['length']}")
        lines.append(f"- Entropy (bits): {e['entropy_bits']}")
        lines.append(f"- Strength: {e['strength']}")
        lines.append(f"- In common wordlist: {e['is_common']}")
        if e.get("common_pattern"):
            lines.append(f"- Contains common pattern: True")
        if e.get("keyboard_pattern"):
            lines.append(f"- Keyboard pattern detected: True")
        if e.get("sequential"):
            lines.append(f"- Sequential pattern detected: True")

        # Recommendations
        for r in e["recommendations"]:
            lines.append(f"- Recommendation: {r}")

        # Crack times (markdown table)
        lines.append("\n**Estimated crack times (by attacker profile):**\n")
        lines.append(format_crack_table(e["crack_times"]))
        lines.append("\n")
        if e["strength"] == "Weak":
            weak_count += 1

    # Summary
    lines.append("## Summary\n")
    lines.append(f"- Total passwords analyzed: {len(entries)}")
    lines.append(f"- Weak passwords: {weak_count}")
    lines.append(f"- Strong passwords: {len(entries) - weak_count}\n")

    return "\n".join(lines)

def pretty_console_output(entries: list):
    """Print a colored table to console using rich for quick inspection."""
    t = Table(show_header=True, header_style="bold magenta")
    t.add_column("Entry", justify="right")
    t.add_column("Masked")
    t.add_column("Len", justify="right")
    t.add_column("Entropy", justify="right")
    t.add_column("Strength")
    t.add_column("Quick crack (online low)")

    for i, e in enumerate(entries, 1):
        pw = e["password"]
        if len(pw) > 4:
            masked = f"{pw[:2]}***{pw[-2:]}"
        elif len(pw) > 2:
            masked = f"{pw[0]}***{pw[-1]}"
        else:
            masked = "***"
        quick = e["crack_times"]["online_low"]["display"]
        t.add_row(str(i), masked, str(e["length"]), str(e["entropy_bits"]), e["strength"], quick)

    console.print(t)

# --- CLI -----------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Password Auditor — use only in a controlled lab environment")
    parser.add_argument("--password", type=str, help="Password to audit")
    parser.add_argument("--input-file", type=str, help="File with passwords, one per line")
    parser.add_argument("--output", type=str, help="Markdown output file")
    parser.add_argument("--no-pretty", action="store_true", help="Disable pretty console table")
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
        console.print("Enter a password:")
        pw = console.input("Password: ")
        entries.append(analyze_password(pw, wordlist))

    # console table
    if not args.no_pretty:
        pretty_console_output(entries)

    report = format_report(entries)
    if args.output:
        Path(args.output).write_text(report, encoding="utf8")
        console.print(f"[green]Report saved to {args.output}")
    else:
        console.print(report)

if __name__ == "__main__":
    main()
