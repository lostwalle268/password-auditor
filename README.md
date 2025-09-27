# Password Auditor

An educational **Password Auditor** built with Python.
This project evaluates password strength, detects common weak patterns, and generates clear, human-readable reports.

⚠️ **Disclaimer:** This tool is strictly for **educational and authorized use only**.
Do not use it to audit accounts, systems, or data you do not own or lack explicit permission to test.

---

## Features

* Entropy-based password strength estimation.
* Detection of common passwords via a bundled wordlist (`wordlists/common_passwords.txt`).
* Basic checks for patterns like sequential characters and repeated characters.
* Generates a Markdown report with recommendations.
* Unit tests included (`pytest`).

---

## Project Structure

```
password-auditor/
├── auditor.py              # Main CLI application
├── utils.py                # Helper functions (entropy, pattern checks)
├── wordlists/
│   └── common_passwords.txt
├── tests/
│   ├── test_entropy.py
│   └── test_checks.py
├── requirements.txt        # Dependencies
└── README.md               # Project documentation
```

---

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/password-auditor.git
   cd password-auditor
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

Run the auditor against a password file:

```bash
python auditor.py passwords.txt
```

Or check a single password:

```bash
python auditor.py --password "My$ecureP@ss123"
```

The script will generate a Markdown report with findings.

---

## Example Output

```
Password: My$ecureP@ss123
Entropy: 65.21 bits
Strength: Strong
Notes:
- Not found in common password list
- No simple sequences detected
- No repeated characters detected
```

---

## Running Tests

Run all unit tests with:

```bash
pytest
```

---

## Next Steps

* Add integration with `zxcvbn` for advanced strength checks.
* Implement GitHub Actions for continuous integration.
* Expand wordlists and add breach database checks (with consent).

---

## License

This project is released under the MIT License.
See [LICENSE](LICENSE) for details.
