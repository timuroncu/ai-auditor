# AI Code Auditor

## Overview
This project uses Semgrep to scan code for vulnerabilities and prepares results for AI analysis.

## Features

- 🔍 Recursively scans entire GitHub repositories
- 🛡️ Uses Semgrep's comprehensive security rulesets
- 📁 Preserves directory structure during analysis
- 🔐 Secure configuration via environment variables
- 📊 Detailed vulnerability reporting with severity levels

## Requirements
- Python 3.10+
- pip
- Semgrep CLI
- GitHub Personal Access Token

## Installation

1. **Clone the repository:**
```bash
git clone https://github.com/yourusername/ai-auditor.git
cd ai-auditor
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Configure environment:**
```bash
# Copy the example environment file
copy env.example.txt .env

# Edit .env with your GitHub credentials
# - REPO: owner/repository-name
# - BRANCH: branch to scan (e.g., main)
# - GITHUB_TOKEN: your GitHub personal access token
```

## Usage

Run the scanner:
```bash
python scan.py
```

The script will:
1. Fetch all files from the specified GitHub repository
2. Download them to a temporary directory
3. Run Semgrep security analysis
4. Display vulnerabilities found
5. Save detailed results to `results.json`

## Configuration

Edit your `.env` file with these variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `REPO` | GitHub repository (owner/repo) | `username/repository-name` |
| `BRANCH` | Branch to scan | `main` |
| `GITHUB_TOKEN` | GitHub Personal Access Token | Required |
| `RULES_PATH` | Semgrep ruleset | `p/ci` |
| `OUTPUT_FILE` | Output JSON file | `results.json` |
| `TEMP_DIR` | Temporary download directory | `temp_repo` |
| `DISABLE_SSL_VERIFY` | Disable SSL verification (corporate proxies) | `false` |

## GitHub Token Setup

1. Go to GitHub → Settings → Developer settings → Personal access tokens
2. Generate a new token (classic)
3. Select scopes:
   - `repo` (for private repositories)
   - `public_repo` (for public repositories only)
4. Copy the token and add it to your `.env` file

## Output

The scanner provides:
- Console output with scan progress
- Detailed vulnerability information including:
  - Check ID (rule name)
  - Severity level
  - File path and line number
  - Description message
- Complete results in `results.json`

## Security Note

⚠️ Never commit your `.env` file or expose your GitHub token. The `.gitignore` file is configured to exclude sensitive files.

## License

See [LICENSE](LICENSE) file for details
