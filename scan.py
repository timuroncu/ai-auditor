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
from program_slicer import build_program_slice

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

# OpenAI Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")

# SSL Configuration (for corporate environments with SSL proxies)
DISABLE_SSL_VERIFY = os.getenv("DISABLE_SSL_VERIFY", "false").lower() == "true"

# Configure SSL verification for Semgrep (corporate proxy workaround)
if DISABLE_SSL_VERIFY:
    os.environ["SEMGREP_DISABLE_CERT_VERIFY"] = "1"
    print("⚠️  SSL certificate verification disabled (corporate proxy mode)")

# Initialize OpenAI client
client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

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
    if not client:
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
        max_lines=600
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

**Respond ONLY in JSON format:**
{{
  "is_vulnerable": true/false,
  "confidence": "high/medium/low",
  "risk_level": "CRITICAL/HIGH/MEDIUM/LOW/INFO",
  "reasoning": "Detailed explanation based on dataflow analysis, referencing specific variables, functions, and code sections",
  "recommendation": "Specific fix or explanation of why it's a false positive"
}}"""
    
    try:
        response = client.chat.completions.create(
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

Analyze and respond ONLY in JSON format:
{{
  "is_vulnerable": true/false,
  "confidence": "high/medium/low",
  "risk_level": "CRITICAL/HIGH/MEDIUM/LOW/INFO",
  "reasoning": "Detailed explanation",
  "recommendation": "Specific fix or explanation"
}}"""
    
    try:
        response = client.chat.completions.create(
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

# Step 6: Analyze all vulnerabilities with AI
def ai_analyze_results():
    """Analyze all Semgrep findings with OpenAI"""
    if not client:
        print("\n⚠️  OpenAI API key not configured. Skipping AI analysis.")
        print("   Set OPENAI_API_KEY in your .env file to enable AI analysis.")
        return
    
    print("\n" + "=" * 80)
    print("🤖 Starting AI Analysis of Semgrep Findings...")
    print("=" * 80)
    
    # Load Semgrep results
    with open(OUTPUT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        semgrep_data = json.load(f)
    
    vulnerabilities = semgrep_data.get('results', [])
    
    if not vulnerabilities:
        print("No vulnerabilities to analyze.")
        return
    
    print(f"Analyzing {len(vulnerabilities)} findings with {OPENAI_MODEL}...\n")
    
    analyzed_results = []
    true_positives = 0
    false_positives = 0
    
    for i, vuln in enumerate(vulnerabilities, 1):
        file_path = vuln.get('path', 'Unknown')
        check_id = vuln.get('check_id', 'Unknown')
        
        print(f"[{i}/{len(vulnerabilities)}] Analyzing: {file_path} - {check_id}")
        
        ai_analysis = analyze_vulnerability_with_ai(vuln)
        
        # Combine Semgrep finding with AI analysis
        result = {
            "semgrep_finding": {
                "check_id": check_id,
                "severity": vuln.get('extra', {}).get('severity', 'N/A'),
                "message": vuln.get('extra', {}).get('message', 'N/A'),
                "file": vuln.get('path', 'N/A'),
                "line": vuln.get('start', {}).get('line', 'N/A'),
            },
            "ai_analysis": ai_analysis
        }
        
        analyzed_results.append(result)
        
        if ai_analysis.get('analyzed'):
            if ai_analysis.get('is_vulnerable'):
                true_positives += 1
                print(f"  ✓ TRUE POSITIVE - Risk: {ai_analysis.get('risk_level', 'N/A')}")
            else:
                false_positives += 1
                print(f"  ✗ FALSE POSITIVE")
        else:
            print(f"  ⚠ Analysis failed: {ai_analysis.get('error', 'Unknown error')}")
    
    # Save AI analysis results
    output_data = {
        "repository": REPO,
        "branch": BRANCH,
        "total_findings": len(vulnerabilities),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "model_used": OPENAI_MODEL,
        "results": analyzed_results
    }
    
    with open(AI_ANALYSIS_FILE, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    
    print("\n" + "=" * 80)
    print(f"✅ AI Analysis Complete!")
    print(f"   True Positives: {true_positives}")
    print(f"   False Positives: {false_positives}")
    print(f"   Results saved to: {AI_ANALYSIS_FILE}")
    print("=" * 80)

# Step 7: Display AI-analyzed results
def display_ai_results():
    """Display the AI-analyzed vulnerabilities"""
    if not os.path.exists(AI_ANALYSIS_FILE):
        print("\nNo AI analysis file found. Run AI analysis first.")
        return
    
    with open(AI_ANALYSIS_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        data = json.load(f)
    
    results = data.get('results', [])
    true_positives = [r for r in results if r.get('ai_analysis', {}).get('is_vulnerable')]
    
    if not true_positives:
        print("\n🎉 No true vulnerabilities found! All findings were false positives.")
        return
    
    print(f"\n⚠️  Found {len(true_positives)} True Vulnerabilities:")
    print("=" * 80)
    
    for i, result in enumerate(true_positives, 1):
        semgrep = result.get('semgrep_finding', {})
        ai = result.get('ai_analysis', {})
        
        print(f"\n[{i}] {semgrep.get('check_id', 'Unknown')}")
        print(f"    File: {semgrep.get('file', 'N/A')} (Line {semgrep.get('line', 'N/A')})")
        print(f"    Risk Level: {ai.get('risk_level', 'N/A')} (Confidence: {ai.get('confidence', 'N/A')})")
        print(f"    Reasoning: {ai.get('reasoning', 'N/A')}")
        print(f"    Fix: {ai.get('recommendation', 'N/A')}")
    
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
