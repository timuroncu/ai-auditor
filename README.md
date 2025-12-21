# AI Code Auditor

Multi-agent AI-powered security scanner combining Semgrep static analysis with GPT and Claude models to reduce false positives through consensus voting.

## Features

- Recursive GitHub repository scanning with full directory structure preservation
- Semgrep security analysis with 1300+ rules
- Multi-agent AI voting system (1x GPT + 2x Claude) for false positive reduction
- AST-based program slicing for Python code analysis
- Dataflow-aware vulnerability assessment
- Detailed reporting with risk levels and remediation guidance

## Requirements

- Python 3.9+
- Semgrep CLI
- GitHub Personal Access Token
- OpenAI API Key
- Anthropic Claude API Key

## Installation

```bash
git clone https://github.com/yourusername/ai-auditor.git
cd ai-auditor
pip install -r requirements.txt
```

## Configuration

Create a `.env` file with:

```bash
# GitHub Configuration
REPO=owner/repository-name
BRANCH=main
GITHUB_TOKEN=your_github_token

# OpenAI Configuration (Agent 1)
OPENAI_API_KEY=your_openai_key
OPENAI_MODEL=gpt-4.1-mini

# Anthropic Configuration (Agents 2 & 3)
ANTHROPIC_API_KEY=your_anthropic_key
CLAUDE_MODEL=claude-sonnet-4-20250514

# Output Configuration
OUTPUT_FILE=results.json
AI_ANALYSIS_FILE=ai_analysis.json
TEMP_DIR=temp_repo
RULES_PATH=auto

# SSL Configuration (for corporate proxies)
DISABLE_SSL_VERIFY=false
```

## Usage

```bash
python scan.py
```

The scanner will:
1. Fetch repository files from GitHub
2. Run Semgrep static analysis
3. Analyze findings with 3 AI agents
4. Report confirmed vulnerabilities (2/3 vote required)
5. Save results to `results.json` and `ai_analysis.json`

## Multi-Agent Voting System

Three AI agents independently analyze each Semgrep finding:

**Agent 1: OpenAI GPT-4.1-mini**
- SAST result verification
- Fast and cost-effective
- Uses AST-based program slicing for Python

**Agent 2: Claude Sonnet 4**
- Independent SAST analysis
- Strong reasoning capabilities
- Pattern-based vulnerability detection

**Agent 3: Claude Sonnet 4**
- Independent SAST analysis
- Architecture-aware review
- Exploitability assessment

### Voting Rules

- **3/3 or 2/3 votes**: CONFIRMED VULNERABILITY (high/medium confidence)
- **1/3 vote**: LOW PROBABILITY (likely false positive)
- **0/3 votes**: NOT VULNERABLE (false positive)

All agents receive identical input (Semgrep metadata + code context) to vote on the same vulnerability. Different AI models provide diverse perspectives and reduce systematic errors.

## How It Works

### 1. Static Analysis
Semgrep scans code with security rules and provides dataflow traces.

### 2. Program Slicing (Python only)
For Python files, AST-based slicer extracts:
- Sink context (function containing vulnerability)
- Upstream dataflow (backward trace of suspicious variables)
- Helper/sanitizer functions
- Caller context

For other languages, uses intelligent line-based context extraction.

### 3. AI Voting
Three independent agents analyze each finding:
- Verify vulnerability existence
- Check for input validation/sanitization
- Assess real-world exploitability
- Determine true positive vs false positive

### 4. Consensus Decision
Only findings with 2+ votes are reported as confirmed vulnerabilities.

## API Keys Setup

### GitHub Token
1. GitHub Settings > Developer settings > Personal access tokens
2. Generate new token with `repo` scope
3. Copy to `.env` as `GITHUB_TOKEN`

### OpenAI API Key
1. Visit https://platform.openai.com/api-keys
2. Create new API key
3. Copy to `.env` as `OPENAI_API_KEY`

### Anthropic API Key
1. Visit https://console.anthropic.com/settings/keys
2. Create new API key
3. Copy to `.env` as `ANTHROPIC_API_KEY`

## Cost Estimation

Per vulnerability analysis (all 3 agents):
- Agent 1 (GPT-4.1-mini): ~$0.01-0.02
- Agent 2 (Claude Sonnet 4): ~$0.10-0.15
- Agent 3 (Claude Sonnet 4): ~$0.10-0.15
- **Total**: ~$0.20-0.35 per vulnerability

For a typical scan with 10 findings: ~$2-3.50

Claude is more expensive but provides superior false positive detection and reasoning capabilities.

## Output Files

### results.json
Raw Semgrep findings with:
- Check IDs and severity levels
- File paths and line numbers
- Dataflow traces
- Rule messages

### ai_analysis.json
AI-analyzed results with:
- Voting summary (confirmed/low probability/not vulnerable)
- Individual agent analyses and votes
- Risk assessments
- Remediation recommendations
- Confidence levels

## File Exclusions

The scanner automatically excludes:
- Binary files (images, videos, archives)
- Dependencies (node_modules, vendor, .venv)
- Build outputs (dist, build, target)
- System files (.DS_Store, Thumbs.db)
- Media files (.jpg, .png, .mp4, etc.)
- Documentation (unless it contains code)

## Troubleshooting

### SSL Certificate Errors
If behind corporate proxy, set `DISABLE_SSL_VERIFY=true` in `.env`.

### Semgrep Scanning 0 Files
The scanner uses `--no-git-ignore` to scan all downloaded files.

### Agent Returning No Vote
Agents are configured to always return a vote. Check error messages in `ai_analysis.json` for API issues.

### Model Not Found (404)
Verify model names in `.env`:
- OpenAI: `gpt-4.1-mini` or `gpt-4o-mini`
- Claude: `claude-sonnet-4-20250514` (check your API key has access)

## Security Notes

- Never commit `.env` file (already in `.gitignore`)
- Temporary files (`temp_repo`) are auto-deleted after scan
- All API keys should have appropriate rate limits configured
- GitHub token should have minimal required scopes

## Example Output

```
[1/10] Analyzing: src/api.py:45 - python.lang.security.injection.sql
  Agent 1 (SAST Analyzer)... ✓
  Agent 2 (SAST Analyzer)... ✓
  Agent 3 (SAST Analyzer)... ✓
  VULNERABILITY CONFIRMED (3/3) - Risk: HIGH

Final Summary:
  Confirmed Vulnerabilities (2-3 votes): 3
  Low Probability (1 vote): 5
  Not Vulnerable (0 votes): 2
```

## Architecture Benefits

**Traditional SAST**:
- High false positive rate
- No context awareness
- Pattern matching only

**AI-Auditor**:
- Multi-agent consensus reduces false positives
- Dataflow-aware analysis (Python)
- Context-sensitive reasoning
- Exploitability assessment
- Actionable remediation advice

## License

MIT License - See LICENSE file for details
