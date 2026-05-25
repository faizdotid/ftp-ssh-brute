# ftp-ssh-brute

Modern asynchronous FTP & SSH brute-forcer toolkit using default credential wordlists.

## Features

- **ftp_brute.py** — Fast async FTP brute-forcer with auto-upload proof-of-access.
- **ssh_brute.py** — Fast async SSH brute-forcer with remote command execution check.
- Rich console output with progress spinners and result tables.
- Configurable concurrency, timeouts, and custom wordlists.
- Clean argparse CLI (no more manual input prompts).

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### FTP Brute

```bash
python ftp_brute.py -t targets.txt
python ftp_brute.py -t targets.txt -w ftp-betterdefaultpasslist.txt -c 100 -o results/
```

### SSH Brute

```bash
python ssh_brute.py -t targets.txt
python ssh_brute.py -t targets.txt -w ssh-betterdefaultpasslist.txt -c 100 -p 2222 -o results/
```

## Options

| Flag | Description |
|------|-------------|
| `-t, --targets` | File containing target hosts/URLs |
| `-w, --wordlist` | Credential wordlist (user:pass format) |
| `-c, --concurrency` | Max concurrent connections (default: 50) |
| `-p, --port` | SSH port only (default: 22) |
| `--timeout` | Connection timeout in seconds (default: 15) |
| `-o, --output` | Output directory for result files |

## Wordlist Format

One credential per line:

```
admin:admin
root:root
user:password123
```

## Disclaimer

This tool is intended for authorized security testing and research only. Always obtain proper permission before testing systems you do not own.
