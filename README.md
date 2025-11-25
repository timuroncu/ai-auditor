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

1. **Static Analysis**: Semgrep scans the code with 1330+ security rules and provides dataflow traces
2. **Program Slicing (NEW!)**: For each finding, an AST-based slicer builds a dataflow-aware program slice:
   - **Sink Context**: The complete function containing the vulnerability
   - **Upstream Dataflow**: Backward slice showing how suspicious variables are defined and flow to the sink
   - **Helpers & Sanitizers**: Any validation/sanitization functions that process the data
   - **Callers**: Functions that call the vulnerable code (limited to keep size manageable)
3. **AI Analysis**: GPT-4.1-mini evaluates each finding using the structured program slice:
   - Analyzes the complete dataflow from source to sink
   - Identifies input validation and sanitization
   - Understands helper functions and security controls
   - Determines if it's a real vulnerability or false positive
   - Assigns accurate risk levels based on exploit feasibility
   - Provides specific, actionable remediation advice
4. **Results**: Only true vulnerabilities are reported, with dataflow-aware insights

## Architecture: Dataflow-Aware Program Slicing

Traditional SAST tools often produce false positives because they analyze code patterns in isolation. This tool uses **AST-based program slicing** to provide rich, dataflow-aware context to the LLM:

### What is Program Slicing?

Instead of sending fixed line ranges (e.g., "first 100 lines + ±50 around the bug"), the tool:

1. **Parses the source code** into an Abstract Syntax Tree (AST)
2. **Identifies the sink** (the dangerous operation Semgrep flagged)
3. **Traces suspicious variables** backward through the code
4. **Builds a backward slice** showing how data flows to the vulnerability
5. **Includes helper functions** that might sanitize or validate the data
6. **Adds caller context** to show how data enters the vulnerable function

### Why This Matters

**Example: False Positive Reduction**

```python
# Line 5: Helper function with validation
def sanitize_input(user_input):
    return re.sub(r'[^a-zA-Z0-9]', '', user_input)

# Line 50: Vulnerable-looking code
def search_user(username):
    username = sanitize_input(username)  # ← Sanitization happens here!
    query = f"SELECT * FROM users WHERE name = '{username}'"  # ← Semgrep flags this
    return db.execute(query)
```

**Without program slicing:**
- AI only sees line 52: `query = f"SELECT * FROM users WHERE name = '{username}'"`
- Looks vulnerable → **FALSE POSITIVE** flagged

**With program slicing:**
- AI sees the complete dataflow: `user input → sanitize_input() → query`
- AI reads the `sanitize_input()` function (line 5)
- Understands the input is sanitized → **CORRECTLY IDENTIFIED AS SAFE**

### Supported Languages

- **Python**: Full AST-based slicing with dataflow analysis
- **Other languages**: Fallback to intelligent line-based context extraction

### Fallback Strategy

If AST parsing fails (syntax errors, unsupported language, etc.), the system automatically falls back to the previous method (header + context), ensuring the scanner continues to function.

## Security Note

⚠️ Never commit your `.env` file or expose your GitHub token. The `.gitignore` file is configured to exclude sensitive files.

## License

See [LICENSE](LICENSE) file for details
