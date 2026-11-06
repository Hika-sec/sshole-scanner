# sshole-scanner

A multithreaded SSH scanner for the SSHole vulnerability research workflow. It probes SSH services and attempts authentication using the vendored `ssh.SSHHoleAuth(probe, payload)` method, writing responsive targets to an output file.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-f` | *(empty)* | Targets file path. Each line is loaded as a target (file mode). |
| `-r` | *(empty)* | IP range/CIDR target spec. Supports CIDR, dash ranges, comma-separated entries, and optional per-entry ports. |
| `-p` | `22` | Default port used when a target/range does not specify a port. |
| `-o` | `vulnerable.txt` | Output file path. Vulnerable targets are appended as `ip:port` lines. |
| `-u` | `alpine` | SSH username used for the authentication attempt. |
| `-t` | `50` | Number of worker threads. |
| `-timeout` | `5` | Per-target TCP/SSH timeout in seconds. |
| `-len` | `300` | Payload password length (number of `A` characters sent as the oversized payload). |
| `-v` | `false` | Verbose output. Prints connection/auth rejection details. |

At least one input source is required: `-f` and/or `-r`. If neither is provided, the scanner prints usage and exits.

## Precompiled Binaries

Standalone precompiled binaries are available in the [`releases/`](releases/) folder:
- **Linux (x86_64):** `releases/sshhole-scanner-linux-amd64`
- **Windows (x86_64):** `releases/sshhole-scanner-windows-amd64.exe`

## Build (Go)

The scanner module lives in `scanner/` and uses a local `replace` for `golang.org/x/crypto`:

```text
module sshhole-scanner
go 1.24.4
replace golang.org/x/crypto => ./crypto
```

Build from the `scanner` directory:

```powershell
Set-Location .\scanner
go build -o sshhole-scanner.exe .
```

On Linux/macOS:

```bash
cd scanner
go build -o sshhole-scanner .
```

## File Mode (`-f`) IP List Format

Provide one target per line. Supported line formats:

```text
# comments are ignored
192.168.1.10
192.168.1.11:2222
host.example.com
host.example.com:22
```

Rules:

- Blank lines are ignored.
- Lines starting with `#` are treated as comments.
- If a port is omitted, the scanner uses `-p` (default `22`).
- If a port is present (`ip:port` or `host:port`), that port is used.
- Duplicate targets are skipped.

## Range Mode (`-r`) Format

`-r` accepts comma-separated entries. Examples:

```text
192.168.1.0/24
10.0.0.1-50
10.0.0.1-10.0.0.20
192.168.1.0/24:2222,10.0.0.5:22
```

Rules:

- CIDR entries expand to all addresses in the CIDR block.
- Dash ranges support full end IPs (`start-end`) or a short last-octet end (`x.x.x.1-50`).
- Per-entry ports can be provided (`entry:port` where supported by the parser); otherwise `-p` is used.

## Output

Targets that complete the SSH handshake/auth flow as implemented by the scanner are printed as:

```text
[+] 203.0.113.10:22
```

They are also appended to the output file (`-o`, default `vulnerable.txt`) as plain `ip:port` lines:

```text
203.0.113.10:22
198.51.100.7:2222
```

The final summary reports totals:

```text
done: <scanned> scanned, <vulnerable> vulnerable (saved to <output>)
```

## Usage Examples

Scan from a file:

```powershell
.\scanner\sshhole-scanner.exe -f targets.txt -o vulnerable.txt
```

Scan a CIDR range with a custom port and timeout:

```powershell
.\scanner\sshhole-scanner.exe -r 192.168.1.0/24 -p 22 -t 100 -timeout 3 -v
```

Combine file and range input:

```powershell
.\scanner\sshhole-scanner.exe -f targets.txt -r 10.0.0.1-50 -u alpine -len 300
```

## Notes

- This tool is intended for authorized security testing and vulnerability research only.
- A target is considered "vulnerable" by this scanner when `checkTarget` receives a successful SSH client connection/auth response for the probe+payload sequence it sends.
- The scanner uses `ssh.InsecureIgnoreHostKey()` and should only be used in controlled environments.
