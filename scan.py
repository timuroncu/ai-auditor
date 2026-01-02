import os
import subprocess
import requests
import shutil
import json
import sys
import time
import threading
from typing import Optional
from dotenv import load_dotenv
from openai import OpenAI
from anthropic import Anthropic
from program_slicer import build_program_slice
from local_ml_agent import enabled as local_ml_enabled, vote as local_ml_vote


# Load environment variables from .env file
load_dotenv()

# Set UTF-8 encoding for console output on Windows
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except:
        pass  # If reconfigure fails, continue anyway

# Configuration
REPO = os.getenv("REPO", "username/repository-name")  # GitHub repo (e.g., 'octocat/Hello-World')
BRANCH = os.getenv("BRANCH", "main")  # Branch to scan (e.g., 'main' or 'master')
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "YOUR_GITHUB_TOKEN")  # Your GitHub token
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "results.json")  # Output file for vulnerabilities
AI_ANALYSIS_FILE = os.getenv("AI_ANALYSIS_FILE", "ai_analysis.json")  # AI-analyzed results
TEMP_DIR = os.getenv("TEMP_DIR", "temp_repo")  # Temporary directory to clone repo into
RULES_PATH = os.getenv("RULES_PATH", "auto")  # auto = language-specific rules, or try 'p/security-audit', 'p/owasp-top-ten'

# OpenAI Configuration (Agent 1)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")

# Anthropic Claude Configuration (Agent 2 & 3)
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-20250514")

# SSL Configuration (for corporate environments with SSL proxies)
DISABLE_SSL_VERIFY = os.getenv("DISABLE_SSL_VERIFY", "false").lower() == "true"

# Configure SSL verification for Semgrep (corporate proxy workaround)
if DISABLE_SSL_VERIFY:
    os.environ["SEMGREP_DISABLE_CERT_VERIFY"] = "1"
    print("⚠️  SSL certificate verification disabled (corporate proxy mode)")

# Initialize OpenAI client (Agent 1)
openai_client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

# Initialize Anthropic client (Agent 2 & 3)
claude_client = Anthropic(api_key=ANTHROPIC_API_KEY) if ANTHROPIC_API_KEY else None

# Step 1: Recursively fetch all files in the GitHub repository
def fetch_repo_files_recursive(path=""):
    """Recursively fetch all files from a GitHub repository"""
    url = f"https://api.github.com/repos/{REPO}/contents/{path}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    response = requests.get(url, headers=headers)
    
    if response.status_code != 200:
        print(f"\n❌ Failed to fetch repository files from GitHub")
        print(f"   Repository: {REPO}")
        print(f"   URL: {url}")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}\n")
        
        # Check if using placeholder values
        if REPO == "username/repository-name" or GITHUB_TOKEN == "YOUR_GITHUB_TOKEN":
            print("🔧 CONFIGURATION ERROR:")
            print("   Your .env file still has placeholder values!")
            print("\n   Required steps:")
            print("   1. Create a .env file (copy from env.example.txt)")
            print("   2. Set REPO=owner/repository-name (e.g., REPO=videvelopers/Vulnerable-Flask-App)")
            print("   3. Set GITHUB_TOKEN=your_actual_token")
            print("   4. Get a token from: https://github.com/settings/tokens")
            print()
        elif response.status_code == 404:
            print("💡 POSSIBLE CAUSES:")
            print("   - Repository doesn't exist or is private")
            print("   - GitHub token doesn't have access to this repository")
            print("   - Repository name format should be: owner/repo-name")
            print()
        
        raise Exception(f"Failed to fetch repository files: {response.text}")
    
    items = response.json()
    all_files = []
    
    for item in items:
        if item['type'] == 'file':
            all_files.append(item)
        elif item['type'] == 'dir':
            # Recursively fetch files from subdirectories (show progress inline)
            print(f"\rScanning: {item['path'][:60]:<60}", end='', flush=True)
            all_files.extend(fetch_repo_files_recursive(item['path']))
    
    return all_files

# Step 2: Download files and create the temporary directory structure
def download_files(files):
    if not os.path.exists(TEMP_DIR):
        os.makedirs(TEMP_DIR)

    # System/metadata files to skip
    skip_files = {'.DS_Store', 'Thumbs.db', 'desktop.ini', '.gitkeep', '.gitattributes'}
    
    # Directories to skip (build outputs, dependencies, etc.)
    skip_dirs = {
        'node_modules', '.git', '__pycache__', 'venv', 'env', '.venv',
        'dist', 'build', 'out', 'target', 'bin', 'obj', 
        '.next', '.nuxt', '.cache', 'coverage', '.pytest_cache',
        'vendor', 'packages', 'bower_components'
    }
    
    # File extensions to skip (non-code files that Semgrep can't analyze)
    skip_extensions = {
        # Binary/Images
        '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.webp', '.tiff', '.svg',
        # Media
        '.mp4', '.mp3', '.wav', '.mov', '.avi', '.wmv', '.flv', '.mkv',
        # Documents
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        # Compressed/Archives
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.tgz',
        # Build outputs
        '.class', '.jar', '.war', '.ear', '.exe', '.dll', '.so', '.dylib', 
        '.o', '.a', '.lib', '.pyc', '.pyo', '.pyd',
        # Minified/Generated
        '.min.js', '.min.css', '.map',
        # Fonts
        '.ttf', '.woff', '.woff2', '.eot', '.otf',
        # Other binary
        '.db', '.sqlite', '.sqlite3', '.dat', '.bin'
    }

    downloaded_count = 0
    skipped_count = 0
    failed_count = 0
    total_files = len(files)
    
    # Pre-filter to count what we'll actually download
    files_to_download = []
    for file in files:
        file_name = file['name']
        file_path_lower = file['path'].lower()
        
        # Skip system/metadata files
        if file_name in skip_files:
            skipped_count += 1
            continue
        
        # Skip files in excluded directories
        path_parts = file['path'].split('/')
        if any(skip_dir in path_parts for skip_dir in skip_dirs):
            skipped_count += 1
            continue
        
        # Skip files with excluded extensions
        file_ext = os.path.splitext(file_name)[1].lower()
        if file_ext in skip_extensions:
            skipped_count += 1
            continue
        
        # Skip .min.js files
        if file_name.endswith('.min.js') or file_name.endswith('.min.css'):
            skipped_count += 1
            continue
        
        files_to_download.append(file)
    
    total_to_download = len(files_to_download)
    
    # Download with progress bar
    for idx, file in enumerate(files_to_download, 1):
        file_url = file['download_url']
        file_path = os.path.join(TEMP_DIR, file['path'])
        
        # Create subdirectories if they don't exist
        file_dir = os.path.dirname(file_path)
        if file_dir and not os.path.exists(file_dir):
            os.makedirs(file_dir)

        # Show progress bar
        progress_pct = (idx / total_to_download) * 100
        bar_length = 40
        filled_length = int(bar_length * idx // total_to_download)
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        
        # Truncate filename if too long
        display_name = file['name'][:30]
        print(f"\r[{bar}] {progress_pct:5.1f}% ({idx}/{total_to_download}) {display_name:<30}", end='', flush=True)
        
        try:
            # Use .content to get binary data (works for both text and binary files)
            file_content = requests.get(file_url).content
            with open(file_path, 'wb') as f:  # Write in binary mode
                f.write(file_content)
            downloaded_count += 1
        except Exception as e:
            failed_count += 1
            print(f"\n  ⚠️  Failed: {file['path']}: {e}")
    
    # Clear the progress line and show summary
    print(f"\r{' ' * 120}\r", end='')  # Clear the line
    print(f"✅ Downloaded {downloaded_count} code files.")
    if skipped_count > 0:
        print(f"⏭️  Skipped {skipped_count} non-code files (binaries, images, documents, etc.)")
    if failed_count > 0:
        print(f"⚠️  Failed to download {failed_count} files.")

# Step 3: Run Semgrep vulnerability scan
def show_spinner(stop_event, message="Scanning"):
    """Show an animated spinner while Semgrep is running"""
    spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    idx = 0
    start_time = time.time()
    
    while not stop_event.is_set():
        elapsed = int(time.time() - start_time)
        mins, secs = divmod(elapsed, 60)
        time_str = f"{mins:02d}:{secs:02d}"
        print(f"\r{spinner_chars[idx]} {message}... [{time_str}]", end='', flush=True)
        idx = (idx + 1) % len(spinner_chars)
        time.sleep(0.1)

def run_semgrep():
    # Run semgrep with JSON output to stdout (we'll capture and write it ourselves)
    command = [
        "semgrep", 
        "--config", RULES_PATH,
        "--no-git-ignore",  # Scan all files, not just git-tracked ones
        "--json",  # Output JSON to stdout
        TEMP_DIR
    ]
    
    # Run Semgrep with spinner animation
    stop_spinner = threading.Event()
    spinner_thread = threading.Thread(target=show_spinner, args=(stop_spinner, f"Running Semgrep with {RULES_PATH} rules"))
    spinner_thread.daemon = True
    spinner_thread.start()
    
    try:
        # Capture stdout instead of letting Semgrep write the file
        result = subprocess.run(
            command, 
            check=True, 
            capture_output=True,
            text=False  # Get bytes instead of text to avoid encoding issues
        )
        
        # Stop spinner
        stop_spinner.set()
        spinner_thread.join(timeout=0.5)
        
        # Write the output ourselves with proper UTF-8 encoding
        with open(OUTPUT_FILE, 'wb') as f:  # Write as binary
            f.write(result.stdout)
        
        print(f"\r{' ' * 120}\r", end='')  # Clear the spinner line
        print(f"✅ Semgrep scan complete. Results saved to {OUTPUT_FILE}.")
    except subprocess.CalledProcessError as e:
        # Stop spinner
        stop_spinner.set()
        spinner_thread.join(timeout=0.5)
        print(f"\r{' ' * 120}\r", end='')  # Clear the spinner line
        
        print(f"❌ Error during Semgrep scan (exit code {e.returncode}):")
        
        # Display the actual error message from Semgrep
        if e.stderr:
            try:
                error_msg = e.stderr.decode('utf-8', errors='ignore')
                print(f"\nSemgrep Error Output:")
                print("=" * 80)
                print(error_msg)
                print("=" * 80)
            except:
                print(f"  (Could not decode error message)")
        
        # Try to save any output we got
        if e.stdout:
            try:
                with open(OUTPUT_FILE, 'wb') as f:
                    f.write(e.stdout)
                print(f"\n  Partial results saved to {OUTPUT_FILE}")
            except:
                pass
        
        # Check for SSL-related errors
        if e.stderr and b'SSL' in e.stderr or b'certificate' in e.stderr:
            print("\n💡 SSL Certificate Error Detected!")
            print("  You're likely behind a corporate proxy with SSL inspection.")
            print("\n  Fix: Set DISABLE_SSL_VERIFY=true in your .env file")
            print("  Then run the scanner again.")
        else:
            print("\n💡 Common fixes:")
            print("  - Ensure Semgrep is installed: pip install semgrep")
            print("  - Check if temp_repo directory exists and has scannable files")
            print("  - Try running: semgrep --version")
        
        return False
    except Exception as e:
        # Stop spinner
        stop_spinner.set()
        spinner_thread.join(timeout=0.5)
        print(f"\r{' ' * 120}\r", end='')  # Clear the spinner line
        
        print(f"❌ Unexpected error during Semgrep scan: {e}")
        return False
    return True

# Step 4: Read entire file content for AI analysis
def read_file_content(file_path, vuln_start_line=None, vuln_end_line=None):
    """Read the entire file content for comprehensive AI analysis"""
    # Normalize the path - replace forward slashes with OS-specific separators
    normalized_path = file_path.replace('/', os.sep).replace('\\', os.sep)
    
    # If the path already includes temp_dir prefix, don't add it again
    if normalized_path.startswith(TEMP_DIR):
        full_path = normalized_path
    else:
        full_path = os.path.join(TEMP_DIR, normalized_path)
    
    if not os.path.exists(full_path):
        print(f"  Debug: File not found at: {full_path}")
        return None, None
    
    try:
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # If file is too large (>50KB), return snippet: first 100 lines + context around vulnerability
        if len(content) > 50000:
            lines = content.split('\n')
            snippet = read_code_snippet(lines, vuln_start_line, vuln_end_line, header_lines=100, context_lines=50)
            return snippet, "snippet"
        
        return content, "full"
    except Exception as e:
        print(f"  Warning: Could not read {file_path}: {e}")
        return None, None

def read_code_snippet(lines, vuln_start_line, vuln_end_line, header_lines=100, context_lines=50):
    """
    Read code snippet for large files with:
    1. First 100 lines (imports, globals, setup)
    2. Context around vulnerability (50 lines before/after)
    """
    if not vuln_start_line:
        # Fallback: return first header_lines if no vuln line specified
        snippet = "\n".join(lines[:header_lines])
        return snippet + "\n\n... (file truncated - showing first 100 lines)"
    
    snippet_lines = []
    
    # Part 1: First 100 lines (imports, globals, class definitions)
    snippet_lines.append("=" * 80)
    snippet_lines.append("FILE HEADER (First 100 lines - imports, globals, setup):")
    snippet_lines.append("=" * 80)
    for i in range(min(header_lines, len(lines))):
        line_num = i + 1
        snippet_lines.append(f"{line_num:6}: {lines[i]}")
    
    # Check if vulnerability is in the first 100 lines
    if vuln_start_line <= header_lines:
        # Vulnerability is already in the header section
        snippet_lines.append("\n" + "=" * 80)
        snippet_lines.append("NOTE: Vulnerable lines are shown above in the header section")
        snippet_lines.append("=" * 80)
        return "\n".join(snippet_lines)
    
    # Part 2: Context around vulnerability (50 lines before/after)
    vuln_context_start = max(header_lines, vuln_start_line - context_lines - 1)  # -1 for 0-based
    vuln_context_end = min(len(lines), vuln_end_line + context_lines)
    
    # Add separation and omission notice
    if vuln_context_start > header_lines:
        snippet_lines.append("\n" + "=" * 80)
        snippet_lines.append(f"... (lines {header_lines + 1}-{vuln_context_start} omitted) ...")
        snippet_lines.append("=" * 80)
    
    snippet_lines.append("\n" + "=" * 80)
    snippet_lines.append(f"VULNERABILITY CONTEXT (±{context_lines} lines around flagged code):")
    snippet_lines.append("=" * 80)
    
    for i in range(vuln_context_start, vuln_context_end):
        line_num = i + 1
        snippet_lines.append(f"{line_num:6}: {lines[i]}")
    
    # Add end notice if there's more content
    if vuln_context_end < len(lines):
        snippet_lines.append("\n" + "=" * 80)
        snippet_lines.append(f"... (lines {vuln_context_end + 1}-{len(lines)} omitted) ...")
        snippet_lines.append("=" * 80)
    
    return "\n".join(snippet_lines)

# Step 5: Analyze a single vulnerability with OpenAI using dataflow-aware program slicing
def analyze_vulnerability_with_ai(vulnerability):
    """Use OpenAI to analyze if a Semgrep finding is a true positive using AST-based program slicing"""
    if not openai_client:
        return {
            "analyzed": False,
            "error": "OpenAI API key not configured"
        }
    
    # Extract vulnerability details
    check_id = vulnerability.get('check_id', 'Unknown')
    severity = vulnerability.get('extra', {}).get('severity', 'N/A')
    message = vulnerability.get('extra', {}).get('message', 'N/A')
    file_path = vulnerability.get('path', 'N/A')
    start_line = vulnerability.get('start', {}).get('line', 1)
    end_line = vulnerability.get('end', {}).get('line', start_line)
    dataflow_trace = vulnerability.get('dataflow_trace', {})
    
    # Read full file content
    full_file_content = read_full_file_for_slicing(file_path)
    
    if not full_file_content:
        return {
            "analyzed": False,
            "error": "Could not read source code"
        }
    
    # Try to build a program slice using AST analysis
    program_slice = build_program_slice(
        file_content=full_file_content,
        file_path=file_path,
        sink_line=start_line,
        semgrep_dataflow=dataflow_trace,
        max_lines=1000
    )
    
    # Fallback to old method if slicing fails
    if not program_slice:
        print(f"  Warning: Program slicing failed, using fallback for {file_path}:{start_line}")
        return analyze_vulnerability_with_ai_fallback(vulnerability, full_file_content)
    
    # Build structured prompt with program slice sections
    prompt = f"""You are a security expert analyzing SAST (Static Application Security Testing) findings from Semgrep.

[FINDING]
- Rule ID: {check_id}
- Semgrep Severity: {severity}
- File: {file_path}
- Flagged Lines: {start_line}-{end_line}
- Semgrep Description: {message}

[CODE - STRUCTURED PROGRAM SLICE]

The following is a DATAFLOW-AWARE PROGRAM SLICE showing only the relevant code for this finding:

--- SINK_CONTEXT (Function containing the vulnerability) ---
{program_slice.sink_context}

--- UPSTREAM_DATAFLOW (How suspicious variables are defined and flow to the sink) ---
{program_slice.upstream_dataflow}

--- HELPERS_AND_SANITIZERS (Functions that process the suspicious data) ---
{program_slice.helpers_and_sanitizers}

--- CALLERS_AND_ENTRYPOINTS (Functions that call the vulnerable function) ---
{program_slice.callers_and_entrypoints}

[ANALYSIS TASK]

Analyze this program slice to determine:

1. **Is this a TRUE POSITIVE or FALSE POSITIVE?**
   - TRUE POSITIVE: Real vulnerability that can be exploited
   - FALSE POSITIVE: Safe code with proper sanitization/validation, or acceptable risk

2. **What is the ACTUAL risk level?**
   - CRITICAL: Direct exploit path, immediate danger
   - HIGH: Serious vulnerability, likely exploitable
   - MEDIUM: Vulnerability with limited impact or exploitation difficulty
   - LOW: Minor issue or requires specific conditions
   - INFO: Not a vulnerability, just informational

3. **Why?** Explain your reasoning based on:
   - The dataflow from source to sink
   - Input validation or sanitization in the upstream dataflow
   - Helper/sanitizer functions that process the data
   - Security controls in place
   - How callers pass data into the vulnerable function

4. **What should be done?** If true positive, provide specific fix. If false positive, explain why it's safe.

**CRITICAL: You MUST vote. Set is_vulnerable to either true or false.**

**Respond ONLY in JSON format:**
{{
  "is_vulnerable": true,
  "confidence": "high",
  "risk_level": "MEDIUM",
  "reasoning": "Detailed explanation based on dataflow analysis",
  "recommendation": "Specific fix or explanation"
}}"""
    
    try:
        response = openai_client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specializing in dataflow analysis and code security. You will receive a STRUCTURED PROGRAM SLICE showing: (1) the sink function, (2) upstream dataflow of suspicious variables, (3) helper/sanitizer functions, and (4) callers. Use this dataflow-aware context to accurately identify true vs false positives. Respond only with valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,  # Lower temperature for more consistent analysis
            response_format={"type": "json_object"}
        )
        
        analysis = json.loads(response.choices[0].message.content)
        analysis["analyzed"] = True
        analysis["slice_metadata"] = program_slice.metadata
        return analysis
        
    except Exception as e:
        return {
            "analyzed": False,
            "error": str(e)
        }


def read_full_file_for_slicing(file_path: str) -> Optional[str]:
    """Read the complete file content for AST-based slicing"""
    # Normalize the path
    normalized_path = file_path.replace('/', os.sep).replace('\\', os.sep)
    
    if normalized_path.startswith(TEMP_DIR):
        full_path = normalized_path
    else:
        full_path = os.path.join(TEMP_DIR, normalized_path)
    
    if not os.path.exists(full_path):
        print(f"  Debug: File not found at: {full_path}")
        return None
    
    try:
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception as e:
        print(f"  Warning: Could not read {file_path}: {e}")
        return None


# Agent 2: SAST Analyzer (Claude-powered)
def analyze_with_agent_2(vulnerability):
    """
    Agent 2: SAST Analyzer (Claude-powered)
    Analyzes the flagged file and line to vote on whether it's vulnerable
    """
    if not claude_client:
        return {
            "analyzed": False,
            "error": "Anthropic API key not configured"
        }
    
    # Extract vulnerability details (including Semgrep metadata)
    check_id = vulnerability.get('check_id', 'Unknown')
    severity = vulnerability.get('extra', {}).get('severity', 'N/A')
    message = vulnerability.get('extra', {}).get('message', 'N/A')
    file_path = vulnerability.get('path', 'N/A')
    start_line = vulnerability.get('start', {}).get('line', 1)
    end_line = vulnerability.get('end', {}).get('line', start_line)
    
    # Read the flagged file only (optimized - not entire repo)
    file_content = read_full_file_for_slicing(file_path)
    
    if not file_content:
        return {
            "analyzed": False,
            "error": "Could not read source file"
        }
    
    # For large files, extract smart context
    lines = file_content.split('\n')
    if len(file_content) > 50000:
        # Header + context around flagged line
        header = "\n".join(lines[:100])
        start_ctx = max(0, start_line - 60)
        end_ctx = min(len(lines), end_line + 60)
        context = "\n".join([f"{i+1:4}: {lines[i]}" for i in range(start_ctx, end_ctx)])
        code_to_analyze = f"[File Header - First 100 lines]\n{header}\n\n[Flagged Code Context]\n{context}"
    else:
        # Small file - send everything with line numbers
        code_to_analyze = "\n".join([f"{i+1:4}: {line}" for i, line in enumerate(lines)])
    
    prompt = f"""You are a security expert performing SAST (Static Application Security Testing) analysis.

[SEMGREP DETECTION - What was flagged]
- Rule ID: {check_id}
- Severity: {severity}
- Semgrep's Concern: {message}
- File: {file_path}
- Flagged Lines: {start_line}-{end_line}

[YOUR TASK]
Independently verify if this is a REAL vulnerability by analyzing the actual code.
Perform your own analysis to determine if this is a true positive or false positive.

[CODE TO ANALYZE]
```
{code_to_analyze}
```

[ANALYSIS INSTRUCTIONS]
1. **Focus on lines {start_line}-{end_line}** - this is what Semgrep flagged
2. **Verify the vulnerability**:
   - Is there actually dangerous code at these lines?
   - Is user input involved without sanitization?
   - Are security functions used correctly?
   - Is there proper validation/escaping?

3. **Look for false positive indicators**:
   - Input is validated before use
   - Safe APIs are used (parameterized queries, safe libraries)
   - Data comes from trusted sources only
   - Proper encoding/escaping is applied

4. **Consider the context**:
   - Is this in a security-critical path?
   - What's the data flow?
   - Are there compensating controls?

[VOTE]
Based on YOUR independent analysis, is this a real vulnerability?

**CRITICAL: You MUST vote. Return is_vulnerable as either true or false.**

**Respond with ONLY valid JSON (no markdown, no extra text):**
{{
  "is_vulnerable": true,
  "confidence": "high",
  "risk_level": "MEDIUM",
  "reasoning": "Your analysis here",
  "recommendation": "Your recommendation here"
}}"""
    
    # Combine system message and prompt for Claude
    full_prompt = """You are a security expert. You MUST respond with ONLY valid JSON.

DO NOT use markdown code blocks. DO NOT add any text before or after the JSON.
Your entire response must be parseable JSON starting with {{ and ending with }}.

""" + prompt
    
    try:
        response = claude_client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=2048,
            temperature=0.3,
            messages=[
                {"role": "user", "content": full_prompt}
            ]
        )
        
        # Extract JSON from Claude's response
        response_text = response.content[0].text.strip()
        
        # Try to extract JSON if wrapped in markdown
        if response_text.startswith("```"):
            # Remove markdown code blocks
            lines = response_text.split('\n')
            response_text = '\n'.join([line for line in lines if not line.startswith("```")])
            response_text = response_text.strip()
        
        # Parse JSON
        analysis = json.loads(response_text)
        
        # Ensure is_vulnerable is present and boolean
        if "is_vulnerable" not in analysis:
            analysis["is_vulnerable"] = False  # Default to false if missing
        
        analysis["analyzed"] = True
        analysis["agent_name"] = "agent_2_sast_analyzer"
        return analysis
        
    except json.JSONDecodeError as e:
        # JSON parsing failed - return error with no vote
        return {
            "analyzed": False,
            "error": f"JSON decode error: {str(e)}. Response: {response_text[:100] if 'response_text' in locals() else 'N/A'}",
            "agent_name": "agent_2_sast_analyzer"
        }
    except Exception as e:
        return {
            "analyzed": False,
            "error": str(e),
            "agent_name": "agent_2_sast_analyzer"
        }


# Agent 3: SAST Analyzer (Claude-powered)
def analyze_with_agent_3(vulnerability):
    """
    Agent 3: SAST Analyzer (Claude-powered)
    Analyzes the flagged file and line to vote on whether it's vulnerable
    """
    if not claude_client:
        return {
            "analyzed": False,
            "error": "Anthropic API key not configured"
        }
    
    # Extract vulnerability details (including Semgrep metadata)
    check_id = vulnerability.get('check_id', 'Unknown')
    severity = vulnerability.get('extra', {}).get('severity', 'N/A')
    message = vulnerability.get('extra', {}).get('message', 'N/A')
    file_path = vulnerability.get('path', 'N/A')
    start_line = vulnerability.get('start', {}).get('line', 1)
    end_line = vulnerability.get('end', {}).get('line', start_line)
    
    # Read the flagged file only (optimized)
    file_content = read_full_file_for_slicing(file_path)
    
    if not file_content:
        return {
            "analyzed": False,
            "error": "Could not read source file"
        }
    
    # For large files, extract smart context
    lines = file_content.split('\n')
    if len(file_content) > 50000:
        # Header + context around flagged line
        header = "\n".join(lines[:100])
        start_ctx = max(0, start_line - 60)
        end_ctx = min(len(lines), end_line + 60)
        context = "\n".join([f"{i+1:4}: {lines[i]}" for i in range(start_ctx, end_ctx)])
        code_to_analyze = f"[File Header]\n{header}\n\n[Flagged Context]\n{context}"
    else:
        # Small file - send everything
        code_to_analyze = "\n".join([f"{i+1:4}: {line}" for i, line in enumerate(lines)])
    
    prompt = f"""You are a security expert performing SAST (Static Application Security Testing) analysis.

[SEMGREP DETECTION - What was flagged]
- Rule ID: {check_id}
- Severity: {severity}
- Semgrep's Concern: {message}
- File: {file_path}
- Flagged Lines: {start_line}-{end_line}

[YOUR TASK]
Independently verify if this is a REAL vulnerability by analyzing the actual code.
Perform your own analysis to determine if this is a true positive or false positive.

[CODE TO ANALYZE]
```
{code_to_analyze}
```

[ANALYSIS INSTRUCTIONS]
1. **Focus on lines {start_line}-{end_line}** - this is what Semgrep flagged
2. **Verify the vulnerability**:
   - Is there actually dangerous code at these lines?
   - Is user input involved without sanitization?
   - Are security functions used correctly?
   - Is there proper validation/escaping?

3. **Look for false positive indicators**:
   - Input is validated before use
   - Safe APIs are used (parameterized queries, safe libraries)
   - Data comes from trusted sources only
   - Proper encoding/escaping is applied

4. **Consider the context**:
   - Is this in a security-critical path?
   - What's the data flow?
   - Are there compensating controls?

[VOTE]
Based on YOUR independent analysis, is this a real vulnerability?

**CRITICAL: You MUST vote. Return is_vulnerable as either true or false.**

**Respond with ONLY valid JSON (no markdown, no extra text):**
{{
  "is_vulnerable": true,
  "confidence": "high",
  "risk_level": "MEDIUM",
  "reasoning": "Your analysis here",
  "recommendation": "Your recommendation here"
}}"""
    
    # Combine system message and prompt for Claude
    full_prompt = """You are a security expert. You MUST respond with ONLY valid JSON.

DO NOT use markdown code blocks. DO NOT add any text before or after the JSON.
Your entire response must be parseable JSON starting with {{ and ending with }}.

""" + prompt
    
    try:
        response = claude_client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=2048,
            temperature=0.3,
            messages=[
                {"role": "user", "content": full_prompt}
            ]
        )
        
        # Extract JSON from Claude's response
        response_text = response.content[0].text.strip()
        
        # Try to extract JSON if wrapped in markdown
        if response_text.startswith("```"):
            # Remove markdown code blocks
            lines = response_text.split('\n')
            response_text = '\n'.join([line for line in lines if not line.startswith("```")])
            response_text = response_text.strip()
        
        # Parse JSON
        analysis = json.loads(response_text)
        
        # Ensure is_vulnerable is present and boolean
        if "is_vulnerable" not in analysis:
            analysis["is_vulnerable"] = False  # Default to false if missing
        
        analysis["analyzed"] = True
        analysis["agent_name"] = "agent_3_sast_analyzer"
        return analysis
        
    except json.JSONDecodeError as e:
        # JSON parsing failed - return error with no vote
        return {
            "analyzed": False,
            "error": f"JSON decode error: {str(e)}. Response: {response_text[:100] if 'response_text' in locals() else 'N/A'}",
            "agent_name": "agent_3_sast_analyzer"
        }
    except Exception as e:
        return {
            "analyzed": False,
            "error": str(e),
            "agent_name": "agent_3_sast_analyzer"
        }


def analyze_vulnerability_with_ai_fallback(vulnerability, file_content: str):
    """Fallback analysis using simple line-based context when AST slicing fails"""
    check_id = vulnerability.get('check_id', 'Unknown')
    severity = vulnerability.get('extra', {}).get('severity', 'N/A')
    message = vulnerability.get('extra', {}).get('message', 'N/A')
    file_path = vulnerability.get('path', 'N/A')
    start_line = vulnerability.get('start', {}).get('line', 1)
    end_line = vulnerability.get('end', {}).get('line', start_line)
    
    # Use old method: first 100 lines + context
    lines = file_content.split('\n')
    
    if len(file_content) < 50000:
        # Small file: send everything with markers
        marked_content = ""
        for i, line in enumerate(lines, 1):
            if start_line <= i <= end_line:
                marked_content += f">>> LINE {i} (FLAGGED): {line}\n"
            else:
                marked_content += f"    {i}: {line}\n"
        code_to_send = marked_content
        code_description = f"**FULL FILE** ({len(lines)} lines)"
    else:
        # Large file: header + context
        header_lines = min(100, len(lines))
        header = "\n".join([f"    {i+1:4}: {lines[i]}" for i in range(header_lines)])
        
        if start_line <= header_lines:
            context = "[Vulnerability is in header section above]"
        else:
            start_ctx = max(header_lines, start_line - 50)
            end_ctx = min(len(lines), start_line + 50)
            context_lines = []
            for i in range(start_ctx, end_ctx):
                line_num = i + 1
                prefix = ">>> " if line_num == start_line else "    "
                context_lines.append(f"{prefix}{line_num:4}: {lines[i]}")
            context = "\n".join(context_lines)
        
        code_to_send = f"[Header - First 100 lines]\n{header}\n\n[Vulnerability Context]\n{context}"
        code_description = "**FILE HEADER + CONTEXT** (First 100 lines + ±50 around vulnerability)"
    
    prompt = f"""You are a security expert analyzing SAST findings from Semgrep.

**Finding Details:**
- Rule ID: {check_id}
- Semgrep Severity: {severity}
- File: {file_path}
- Flagged Lines: {start_line}-{end_line}
- Semgrep Description: {message}

{code_description}
```
{code_to_send}
```

**CRITICAL: You MUST vote. Set is_vulnerable to either true or false.**

Analyze and respond ONLY in JSON format:
{{
  "is_vulnerable": true,
  "confidence": "high",
  "risk_level": "MEDIUM",
  "reasoning": "Detailed explanation",
  "recommendation": "Specific fix or explanation"
}}"""
    
    try:
        response = openai_client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert. Analyze the code and respond only with valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            response_format={"type": "json_object"}
        )
        
        analysis = json.loads(response.choices[0].message.content)
        analysis["analyzed"] = True
        analysis["used_fallback"] = True
        return analysis
        
    except Exception as e:
        return {
            "analyzed": False,
            "error": str(e)
        }

# Step 6: Calculate voting results for multi-agent system
def calculate_voting_result(votes_dict):
    """
    Calculate the final voting result from multiple agents.
    
    Voting logic:
    - 1/3 votes = Low probability (not a vulnerability)
    - 2/3 votes = Vulnerability confirmed
    - 3/3 votes = High confidence vulnerability
    
    Args:
        votes_dict: Dictionary of agent votes {agent_name: True/False/None}
    
    Returns:
        Dictionary with voting summary
    """
    # Count votes
    total_agents = len(votes_dict)
    votes_for_vulnerable = sum(1 for vote in votes_dict.values() if vote is True)
    votes_against = sum(1 for vote in votes_dict.values() if vote is False)
    votes_pending = sum(1 for vote in votes_dict.values() if vote is None)
    
    # Determine status
    if votes_for_vulnerable >= 2:
        status = "CONFIRMED_VULNERABILITY"
        confidence = "HIGH" if votes_for_vulnerable == 3 else "MEDIUM"
        is_vulnerable = True
    elif votes_for_vulnerable == 1:
        status = "LOW_PROBABILITY"
        confidence = "LOW"
        is_vulnerable = False
    else:
        status = "NOT_VULNERABLE"
        confidence = "HIGH"
        is_vulnerable = False
    
    return {
        "is_vulnerable": is_vulnerable,
        "status": status,
        "confidence": confidence,
        "votes_for": votes_for_vulnerable,
        "votes_against": votes_against,
        "votes_pending": votes_pending,
        "total_agents": total_agents,
        "vote_ratio": f"{votes_for_vulnerable}/{total_agents}"
    }

# Step 7: Analyze all vulnerabilities with AI
def ai_analyze_results():
    """Analyze all Semgrep findings with multi-agent voting system (OpenAI + Claude)"""
    if not openai_client and not claude_client:
        print("\n⚠️  No AI API keys configured. Skipping AI analysis.")
        print("   Set OPENAI_API_KEY and/or ANTHROPIC_API_KEY in your .env file.")
        return
    
    if not openai_client:
        print("\n⚠️  Warning: OpenAI API key not configured. Agent 1 will be disabled.")
    if not claude_client:
        print("\n⚠️  Warning: Anthropic API key not configured. Agents 2 & 3 will be disabled.")
        return
    
    print("\n" + "=" * 80)
    print("🤖 Starting Multi-Agent AI Analysis (Voting System)")
    print("=" * 80)
    print("📊 Active Agents:")
    if openai_client:
        print(f"   ✓ Agent 1: SAST Analyzer - {OPENAI_MODEL}")
    if claude_client:
        print(f"   ✓ Agent 2: SAST Analyzer - {CLAUDE_MODEL}")
        print(f"   ✓ Agent 3: SAST Analyzer - {CLAUDE_MODEL}")
    print("=" * 80)
    print("🗳️  Voting Rules:")
    print("   - 2-3 votes = CONFIRMED VULNERABILITY ✅")
    print("   - 1 vote   = LOW PROBABILITY ⚠️")
    print("   - 0 votes  = NOT VULNERABLE ✓")
    print("=" * 80)
    
    # Load Semgrep results
    with open(OUTPUT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        semgrep_data = json.load(f)
    
    vulnerabilities = semgrep_data.get('results', [])
    
    if not vulnerabilities:
        print("No vulnerabilities to analyze.")
        return
    
    models_used = []
    if openai_client:
        models_used.append(f"OpenAI {OPENAI_MODEL}")
    if claude_client:
        models_used.append(f"Claude {CLAUDE_MODEL}")
    
    print(f"\nAnalyzing {len(vulnerabilities)} findings with: {' + '.join(models_used)}...\n")
    
    analyzed_results = []
    confirmed_vulnerabilities = 0
    low_probability = 0
    not_vulnerable = 0
    
    for i, vuln in enumerate(vulnerabilities, 1):
        file_path = vuln.get('path', 'Unknown')
        check_id = vuln.get('check_id', 'Unknown')
        start_line = vuln.get('start', {}).get('line', 'N/A')
        
        print(f"[{i}/{len(vulnerabilities)}] Analyzing: {file_path}:{start_line} - {check_id}")
        
        # Agent 1: SAST Analyzer (OpenAI)
        print(f"  Agent 1 (SAST Analyzer)...", end='', flush=True)
        agent_1_analysis = analyze_vulnerability_with_ai(vuln)
        print(f" {'✓' if agent_1_analysis.get('analyzed') else '✗'}")
        
        # Agent 2: SAST Analyzer (Claude)
        print(f"  Agent 2 (SAST Analyzer)...", end='', flush=True)
        agent_2_analysis = analyze_with_agent_2(vuln)
        print(f" {'✓' if agent_2_analysis.get('analyzed') else '✗'}")
        
        # Agent 3: SAST Analyzer (Claude)
        print(f"  Agent 3 (SAST Analyzer)...", end='', flush=True)
        agent_3_analysis = analyze_with_agent_3(vuln)
        print(f" {'✓' if agent_3_analysis.get('analyzed') else '✗'}")
        
        # Initialize voting structure - ALL AGENTS VOTE ON SAME FILE:LINE
        agent_votes = {
            "agent_1_sast_analyzer": agent_1_analysis.get('is_vulnerable') if agent_1_analysis.get('analyzed') else None,
            "agent_2_direct_scanner": agent_2_analysis.get('is_vulnerable') if agent_2_analysis.get('analyzed') else None,
            "agent_3_contextual_reviewer": agent_3_analysis.get('is_vulnerable') if agent_3_analysis.get('analyzed') else None
        }
        
        # Calculate voting result
        voting_result = calculate_voting_result(agent_votes)
        
        # Combine Semgrep finding with ALL agent analyses and voting
        result = {
            "semgrep_finding": {
                "check_id": check_id,
                "severity": vuln.get('extra', {}).get('severity', 'N/A'),
                "message": vuln.get('extra', {}).get('message', 'N/A'),
                "file": vuln.get('path', 'N/A'),
                "line": vuln.get('start', {}).get('line', 'N/A'),
            },
            "agent_analyses": {
                "agent_1_sast_analyzer": agent_1_analysis,
                "agent_2_direct_scanner": agent_2_analysis,
                "agent_3_contextual_reviewer": agent_3_analysis
            },
            "voting": {
                "votes": agent_votes,
                "result": voting_result
            }
        }
        
        analyzed_results.append(result)
        
        # Count by voting status
        if voting_result['status'] == 'CONFIRMED_VULNERABILITY':
            confirmed_vulnerabilities += 1
            print(f"  🔴 VULNERABILITY CONFIRMED ({voting_result['vote_ratio']}) - Risk: {agent_1_analysis.get('risk_level', 'N/A')}")
        elif voting_result['status'] == 'LOW_PROBABILITY':
            low_probability += 1
            print(f"  🟡 LOW PROBABILITY ({voting_result['vote_ratio']}) - Likely false positive")
        else:
            not_vulnerable += 1
            print(f"  🟢 NOT VULNERABLE ({voting_result['vote_ratio']}) - Safe code")
        
        # Show individual agent votes
        votes_display = []
        for agent, vote in agent_votes.items():
            if vote is True:
                votes_display.append(f"✓{agent.split('_')[1]}")
            elif vote is False:
                votes_display.append(f"✗{agent.split('_')[1]}")
            else:
                votes_display.append(f"?{agent.split('_')[1]}")
        print(f"  Votes: [{' | '.join(votes_display)}]")
        print()
    
    # Save AI analysis results with voting
    output_data = {
        "repository": REPO,
        "branch": BRANCH,
        "scan_metadata": {
            "total_findings": len(vulnerabilities),
            "model_used": OPENAI_MODEL,
            "agents_active": 3,
            "agents_total": 3,
            "agent_details": {
                "agent_1": f"SAST Analyzer ({OPENAI_MODEL})",
                "agent_2": f"SAST Analyzer ({CLAUDE_MODEL})",
                "agent_3": f"SAST Analyzer ({CLAUDE_MODEL})"
            }
        },
        "voting_summary": {
            "confirmed_vulnerabilities": confirmed_vulnerabilities,
            "low_probability": low_probability,
            "not_vulnerable": not_vulnerable
        },
        "results": analyzed_results
    }
    
    with open(AI_ANALYSIS_FILE, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    
    print("\n" + "=" * 80)
    print(f"✅ Multi-Agent Analysis Complete!")
    print(f"   🔴 Confirmed Vulnerabilities (2-3 votes): {confirmed_vulnerabilities}")
    print(f"   🟡 Low Probability (1 vote): {low_probability}")
    print(f"   🟢 Not Vulnerable (0 votes): {not_vulnerable}")
    print(f"   Results saved to: {AI_ANALYSIS_FILE}")
    print("=" * 80)

# Step 8: Display AI-analyzed results with voting information
def display_ai_results():
    """Display the AI-analyzed vulnerabilities with multi-agent voting results"""
    if not os.path.exists(AI_ANALYSIS_FILE):
        print("\nNo AI analysis file found. Run AI analysis first.")
        return
    
    with open(AI_ANALYSIS_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        data = json.load(f)
    
    results = data.get('results', [])
    voting_summary = data.get('voting_summary', {})
    
    # Filter confirmed vulnerabilities (2+ votes)
    confirmed_vulns = [r for r in results if r.get('voting', {}).get('result', {}).get('status') == 'CONFIRMED_VULNERABILITY']
    
    if not confirmed_vulns:
        print("\n🎉 No confirmed vulnerabilities found!")
        print("   All findings received less than 2/3 votes from security agents.")
        return
    
    print(f"\n⚠️  Found {len(confirmed_vulns)} Confirmed Vulnerabilities (2-3 votes):")
    print("=" * 80)
    
    for i, result in enumerate(confirmed_vulns, 1):
        semgrep = result.get('semgrep_finding', {})
        voting = result.get('voting', {})
        vote_result = voting.get('result', {})
        votes = voting.get('votes', {})
        
        agents = result.get('agent_analyses', {})
        agent_1 = agents.get('agent_1_sast_analyzer', {})
        agent_2 = agents.get('agent_2_direct_scanner', {})
        agent_3 = agents.get('agent_3_contextual_reviewer', {})
        
        print(f"\n[{i}] {semgrep.get('check_id', 'Unknown')}")
        print(f"    📍 Location: {semgrep.get('file', 'N/A')}:{semgrep.get('line', 'N/A')}")
        print(f"    🗳️  Vote Result: {vote_result.get('vote_ratio', 'N/A')} - {vote_result.get('status', 'N/A')}")
        
        # Show individual agent votes
        print(f"    👥 Agent Votes:")
        vote_symbols = {True: "✓ VULNERABLE", False: "✗ SAFE", None: "? NO VOTE"}
        print(f"       Agent 1 (SAST): {vote_symbols.get(votes.get('agent_1_sast_analyzer'), '?')}")
        print(f"       Agent 2 (Pattern): {vote_symbols.get(votes.get('agent_2_direct_scanner'), '?')}")
        print(f"       Agent 3 (Context): {vote_symbols.get(votes.get('agent_3_contextual_reviewer'), '?')}")
        
        # Show highest risk level from any agent
        risk_levels = [agent_1.get('risk_level'), agent_2.get('risk_level'), agent_3.get('risk_level')]
        risk_levels = [r for r in risk_levels if r]
        highest_risk = max(risk_levels, key=lambda x: {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}.get(x, 0)) if risk_levels else 'N/A'
        
        print(f"    🎯 Risk Level: {highest_risk} (Confidence: {vote_result.get('confidence', 'N/A')})")
        
        # Show reasoning from agent who voted vulnerable (prefer Agent 1)
        reasoning = None
        recommendation = None
        if agent_1.get('is_vulnerable'):
            reasoning = agent_1.get('reasoning', '')
            recommendation = agent_1.get('recommendation', '')
        elif agent_2.get('is_vulnerable'):
            reasoning = agent_2.get('reasoning', '')
            recommendation = agent_2.get('recommendation', '')
        elif agent_3.get('is_vulnerable'):
            reasoning = agent_3.get('reasoning', '')
            recommendation = agent_3.get('recommendation', '')
        
        if reasoning:
            print(f"    💡 Analysis: {reasoning[:200]}...")
        if recommendation:
            print(f"    🔧 Fix: {recommendation[:200]}...")
    
    print("=" * 80)
    print(f"\n📊 Final Voting Summary:")
    print(f"   🔴 Confirmed Vulnerabilities (2-3 votes): {voting_summary.get('confirmed_vulnerabilities', 0)}")
    print(f"   🟡 Low Probability (1 vote): {voting_summary.get('low_probability', 0)}")
    print(f"   🟢 Not Vulnerable (0 votes): {voting_summary.get('not_vulnerable', 0)}")
    print("=" * 80)

# Step 8: Clean up the temporary files
def cleanup():
    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)
        print("\nTemporary files deleted.")

# Step 9: Load and display vulnerabilities from the JSON output
def load_vulnerabilities():
    with open(OUTPUT_FILE, 'r', encoding='utf-8', errors='ignore') as file:
        data = json.load(file)
    
    # Extract the results array from Semgrep JSON output
    vulnerabilities = data.get('results', [])
    errors = data.get('errors', [])
    
    # Display some info about the vulnerabilities
    if vulnerabilities:
        print(f"\nFound {len(vulnerabilities)} vulnerabilities:")
        print("=" * 80)
        for i, vuln in enumerate(vulnerabilities[:10], 1):  # Display the first 10
            print(f"\n[{i}] {vuln.get('check_id', 'Unknown')}")
            print(f"    Severity: {vuln.get('extra', {}).get('severity', 'N/A')}")
            print(f"    File: {vuln.get('path', 'N/A')}")
            print(f"    Line: {vuln.get('start', {}).get('line', 'N/A')}")
            print(f"    Message: {vuln.get('extra', {}).get('message', 'N/A')}")
        if len(vulnerabilities) > 10:
            print(f"\n... and {len(vulnerabilities) - 10} more vulnerabilities.")
        print("=" * 80)
    else:
        print("\nNo vulnerabilities found.")
    
    if errors:
        print(f"\nWarning: {len(errors)} errors occurred during scanning.")
        for error in errors[:3]:
            print(f"  - {error}")

# Main function
def main():
    try:
        print("=" * 80)
        print("🔍 AI-Powered Security Auditor")
        print("=" * 80)
        
        print("\n[1/5] Fetching repository files recursively...")
        files = fetch_repo_files_recursive()
        print(f"\r{' ' * 120}\r", end='')  # Clear the scanning line
        print(f"✅ Found {len(files)} files in repository.")

        # Download the files to the temporary directory
        print("\n[2/5] Downloading files from GitHub...")
        download_files(files)

        # Run the Semgrep scan
        print("\n[3/5] Running Semgrep scan...")
        if run_semgrep():
            # Load and print the raw vulnerabilities
            print("\n[4/5] Semgrep Results:")
            load_vulnerabilities()
            
            # Run AI analysis on the findings
            print("\n[5/5] AI Analysis:")
            ai_analyze_results()
            
            # Display AI-analyzed results
            display_ai_results()
        else:
            print("Semgrep scan failed. Skipping AI analysis.")
        
    finally:
        # Cleanup temporary files
        cleanup()

# Run the main function
if __name__ == "__main__":
    main()
