# skgre

skgre - SSH Key GitHub Repository Enumerator. Uses a GitHub SSH key to identify the associated account and enumerate accessible repositories by testing names from a wordlist.

----------

## Requirements

-   Go 1.21+
-   `git` and `ssh` available in PATH
-   A valid GitHub SSH private key with correct permissions (`chmod 600`)

## Installation

```bash
go install -v github.com/AliHzSec/skgre@latest
```

----------

## Modes

### information

Identifies the GitHub account associated with the SSH key and lists organization memberships.

```bash
skgre -m information -i ~/.ssh/id_rsa

```

Output:

```
octocat - https://github.com/octocat
myorg   - https://github.com/myorg

```

----------

### enumeration

Tests repository names against the authenticated user's account using `git ls-remote`.

**Single word:**

```bash
skgre -m enumeration -i ~/.ssh/id_rsa -w secret-repo

```

**Wordlist:**

```bash
skgre -m enumeration -i ~/.ssh/id_rsa -W wordlist.txt -t 20

```

Output:

```
https://github.com/octocat/secret-repo       <- found (green)
https://github.com/octocat/internal-api      <- not found (yellow)

```

**Show only found repositories:**

```bash
skgre -m enumeration -i ~/.ssh/id_rsa -W wordlist.txt -x

```

**Save results to file:**

```bash
skgre -m enumeration -i ~/.ssh/id_rsa -W wordlist.txt -o
skgre -m enumeration -i ~/.ssh/id_rsa -W wordlist.txt -o -op /tmp/results/

```

Output file is named `repo_found_<username>_<timestamp>.txt`.

----------

## Fuzzing

Fuzz mode appends or prepends words to each base word, expanding the candidate list.

**Suffix (default direction):**

```bash
skgre -m enumeration -i ~/.ssh/id_rsa -W repos.txt -F -fs -fw "dev,prod,backup"

```

Generates: `repo-dev`, `repo-prod`, `repo-backup` for each word in the list.

**Prefix:**

```bash
skgre -m enumeration -i ~/.ssh/id_rsa -W repos.txt -F -fp -ff fuzz-words.txt

```

Generates: `dev-repo`, `prod-repo`, `backup-repo` for each word.

## Flags
 
| Flag | Description |
|------|-------------|
| `-m` | Mode: `information` or `enumeration` |
| `-i` | Path to SSH private key |
| `-w` | Single repository name to check |
| `-W` | Path to wordlist file |
| `-t` | Number of threads (default: 10) |
| `-x` | Show only existing repositories |
| `-F` | Enable fuzzing mode |
| `-fp` | Attach fuzz word before base word |
| `-fs` | Attach fuzz word after base word |
| `-fw` | Comma-separated fuzz words |
| `-ff` | Path to fuzz words file |
| `-o` | Save found repositories to file |
| `-op` | Output directory for results file |
| `-s` | Silent mode |
| `-nc` | Disable colors |
| `-d` | Debug mode (show raw git output) |
 
---

## License

MIT