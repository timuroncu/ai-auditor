# AI Code Auditor

## Overview
An AI-powered security scanner that combines Semgrep's static analysis with OpenAI's GPT-4o-mini to intelligently filter false positives and provide accurate vulnerability assessments.

## Features

- 🔍 Recursively scans entire GitHub repositories
- 🛡️ Uses Semgrep's comprehensive security rulesets (1330+ rules)
- 🤖 AI-powered analysis to reduce false positives
- 📁 Preserves directory structure during analysis
- 🔐 Secure configuration via environment variables
- 📊 Detailed vulnerability reporting with severity levels
- 🎯 Intelligent risk assessment and remediation suggestions

## Requirements
- Python 3.10+
- pip
- Semgrep CLI
- GitHub Personal Access Token
- OpenAI API Key (for AI analysis)

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

# Edit .env with your credentials:
# - REPO: owner/repository-name
# - BRANCH: branch to scan (e.g., main)
# - GITHUB_TOKEN: your GitHub personal access token
# - OPENAI_API_KEY: your OpenAI API key
```

## Usage

Run the scanner:
```bash
python scan.py
```

The script will:
1. Fetch all files from the specified GitHub repository
2. Download them to a temporary directory
3. Run Semgrep security analysis (1330+ rules)
4. Analyze each finding with AI to filter false positives
5. Display true vulnerabilities with risk assessments
6. Save detailed results to `results.json` and `ai_analysis.json`

## Configuration

Edit your `.env` file with these variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `REPO` | GitHub repository (owner/repo) | `username/repository-name` |
| `BRANCH` | Branch to scan | `main` |
| `GITHUB_TOKEN` | GitHub Personal Access Token | Required |
| `OPENAI_API_KEY` | OpenAI API Key | Required |
| `OPENAI_MODEL` | OpenAI model to use | `gpt-4o-mini` |
| `RULES_PATH` | Semgrep ruleset | `p/ci` |
| `OUTPUT_FILE` | Semgrep output JSON file | `results.json` |
| `AI_ANALYSIS_FILE` | AI-analyzed results file | `ai_analysis.json` |
| `TEMP_DIR` | Temporary download directory | `temp_repo` |
| `DISABLE_SSL_VERIFY` | Disable SSL verification (corporate proxies) | `false` |

## API Keys Setup

### GitHub Token
1. Go to GitHub → Settings → Developer settings → Personal access tokens
2. Generate a new token (classic)
3. Select scopes:
   - `repo` (for private repositories)
   - `public_repo` (for public repositories only)
4. Copy the token and add it to your `.env` file

### OpenAI API Key
1. Go to [OpenAI Platform](https://platform.openai.com/api-keys)
2. Create a new API key
3. Copy the key and add it to your `.env` file
4. The tool uses GPT-4o-mini for cost-effective analysis

## Output

The scanner provides:

### Console Output
- Real-time scan progress
- Semgrep findings summary
- AI analysis progress with true/false positive classification
- Final vulnerability report with:
  - Risk level (CRITICAL/HIGH/MEDIUM/LOW/INFO)
  - AI confidence level
  - Reasoning for the assessment
  - Remediation recommendations

### Files Generated
- `results.json` - Raw Semgrep findings
- `ai_analysis.json` - AI-analyzed results with:
  - True positives vs false positives count
  - Detailed analysis for each finding
  - Risk assessments and fix recommendations

## How It Works

1. **Static Analysis**: Semgrep scans the code with 1330+ security rules
2. **Context Extraction**: For each finding, the tool extracts surrounding code context
3. **AI Analysis**: GPT-4o-mini evaluates each finding by:
   - Reading the actual code and context
   - Understanding the security rule that triggered
   - Determining if it's a real vulnerability or false positive
   - Assigning accurate risk levels
   - Providing actionable remediation advice
4. **Results**: Only true vulnerabilities are reported, with AI-enhanced insights

## Security Note

⚠️ Never commit your `.env` file or expose your GitHub token. The `.gitignore` file is configured to exclude sensitive files.

## License

See [LICENSE](LICENSE) file for details
