# Password Auditor

An educational, **offline** Python tool to analyze password strength, detect weak patterns, and estimate *theoretical* crack times based on entropy.  
Designed for learning and to include in a cybersecurity portfolio — **use only in environments you control or where you have explicit permission**.

---

## Features
- Entropy-based strength estimation (bits).
- Detection of common passwords via bundled wordlist (`wordlists/common_passwords.txt`).
- Detection of keyboard patterns (e.g., `qwerty`) and sequential runs (e.g., `abcd`, `1234`).
- Recommendations to improve passwords (length, diversity, symbols).
- **Estimated crack times** for several attacker profiles (based on `2^entropy / guesses_per_second`).
- Pretty console table output using `rich` and Markdown report export.
- Simple unit tests with `pytest`.

---

## Quick install

```bash
git clone https://github.com/yourusername/password-auditor.git
cd password-auditor
python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
# source venv/bin/activate

pip install -r requirements.txt
```

`requirements.txt` should include:
```
rich
pytest
```

(If you later want to integrate `zxcvbn` for a more realistic strength model, you can — see *Optional integrations* below.)

---

## How it estimates crack time (brief)
If a password has `E` bits of entropy, the approximate number of possible combinations is `2^E`.  
If an attacker can make `R` guesses per second, the time to try the whole space is:

```
T_seconds = 2**E / R
```

This tool reports that value for several *illustrative* attacker speeds (see profiles below). These are theoretical worst-case/exhaustive-search estimates — real-world cracking behavior varies (hashing algorithm, salts, throttling, distributed attackers, precomputed attacks, etc.).

---

## Attacker profiles (defaults)
These are the built-in illustrative profiles and their default guessing rates used to compute estimates:

| Profile      | Guesses/sec         | Typical scenario (illustrative) |
|--------------|---------------------:|---------------------------------|
| `online_low` | 10                  | Online login attempts (throttled) |
| `online_high`| 100                 | Lenient online endpoints or distributed attempts |
| `single_gpu` | 10,000,000 (1e7)    | A single powerful GPU against fast hashes |
| `gpu_rig`    | 1,000,000,000 (1e9) | Multi-GPU rig / cloud GPUs |
| `asic_farm`  | 10,000,000,000 (1e10) | Large specialized cracking farm |

> **Important:** these values are illustrative. Real cracking speeds depend on the hash algorithm (bcrypt/argon2 are intentionally slow), the presence of salts, and attacker resources.

---

## Usage

### Audit a single password (console + pretty table + markdown output)
```bash
python auditor.py --password "My$ecureP@ss123" --output report.md
```

### Audit many passwords from a file (one per line)
```bash
python auditor.py --input-file examples/passwords.txt --output examples/report.md
```

### Disable pretty console table
```bash
python auditor.py --password "123456" --no-pretty
```

---

## What the tool checks
- Length
- Bits of entropy (simple character-set estimate: lower, upper, digits, symbols)
- Presence in `wordlists/common_passwords.txt`
- Common pattern matches (pattern rules in `utils.py`)
- Keyboard patterns (simple substring check)
- Sequential characters (heuristic)
- Recommendations (how to improve)

---

## Optional integrations (advanced)
- **zxcvbn**: integrate `zxcvbn-python` for a more user-focused strength score and richer feedback. If you add it, you can include `zxcvbn` results alongside entropy-based estimates.
- **Have I Been Pwned** (HIBP) API: check if a password was seen in breaches (use only with consent; requires API integration and careful handling — do **not** send raw passwords to third-party services unless you understand privacy implications).

---

## Testing
Run unit tests:
```bash
pytest
```

---

## Security & legal notes (read carefully)
- **Use only on passwords you own or are authorized to test.**  
- Do not upload real or sensitive passwords to public repos. The project is educational.  
- Crack time estimates assume offline exhaustive guessing; online systems and proper password hashing can make brute-force impractical.

---

## Contributing
- Improve entropy calculation (e.g., add pattern-aware entropy models).
- Add more comprehensive wordlists (keep them offline/private if they contain real leaked data).
- Add CI (GitHub Actions) to run `pytest` and linting on push.

---

## License
MIT — include `LICENSE` in the repo.
