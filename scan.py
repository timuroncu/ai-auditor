import os
import subprocess
import requests
import shutil
import json
import sys
from dotenv import load_dotenv
from openai import OpenAI

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
RULES_PATH = os.getenv("RULES_PATH", "p/ci")  # Semgrep's classical ruleset for vulnerability scanning

# OpenAI Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")

# Initialize OpenAI client
client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

# Step 1: Recursively fetch all files in the GitHub repository
def fetch_repo_files_recursive(path=""):
    """Recursively fetch all files from a GitHub repository"""
    url = f"https://api.github.com/repos/{REPO}/contents/{path}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    response = requests.get(url, headers=headers)
    
    if response.status_code != 200:
        raise Exception(f"Failed to fetch repository files: {response.text}")
    
    items = response.json()
    all_files = []
    
    for item in items:
        if item['type'] == 'file':
            all_files.append(item)
        elif item['type'] == 'dir':
            # Recursively fetch files from subdirectories
            print(f"Scanning directory: {item['path']}")
            all_files.extend(fetch_repo_files_recursive(item['path']))
    
    return all_files

# Step 2: Download files and create the temporary directory structure
def download_files(files):
    if not os.path.exists(TEMP_DIR):
        os.makedirs(TEMP_DIR)

    # Files to skip (system files, metadata, etc.)
    skip_files = {'.DS_Store', 'Thumbs.db', 'desktop.ini'}
    # Directories to skip
    skip_dirs = {'node_modules', '.git', '__pycache__', 'venv', 'env', '.venv'}

    downloaded_count = 0
    for file in files:
        # Skip system/metadata files
        if file['name'] in skip_files:
            continue
        
        # Skip files in excluded directories
        path_parts = file['path'].split('/')
        if any(skip_dir in path_parts for skip_dir in skip_dirs):
            continue
        
        file_url = file['download_url']
        file_path = os.path.join(TEMP_DIR, file['path'])
        
        # Create subdirectories if they don't exist
        file_dir = os.path.dirname(file_path)
        if file_dir and not os.path.exists(file_dir):
            os.makedirs(file_dir)

        print(f"Downloading {file['path']}...")
        try:
            # Use .content to get binary data (works for both text and binary files)
            file_content = requests.get(file_url).content
            with open(file_path, 'wb') as f:  # Write in binary mode
                f.write(file_content)
            downloaded_count += 1
        except Exception as e:
            print(f"  Warning: Failed to download {file['path']}: {e}")
    
    print(f"Downloaded {downloaded_count} files.")

# Step 3: Run Semgrep vulnerability scan
def run_semgrep():
    # Run semgrep with JSON output to stdout (we'll capture and write it ourselves)
    command = [
        "semgrep", 
        "--config", RULES_PATH,
        "--no-git-ignore",  # Scan all files, not just git-tracked ones
        "--json",  # Output JSON to stdout
        TEMP_DIR
    ]
    
    # Run Semgrep and capture output
    try:
        # Capture stdout instead of letting Semgrep write the file
        result = subprocess.run(
            command, 
            check=True, 
            capture_output=True,
            text=False  # Get bytes instead of text to avoid encoding issues
        )
        
        # Write the output ourselves with proper UTF-8 encoding
        with open(OUTPUT_FILE, 'wb') as f:  # Write as binary
            f.write(result.stdout)
        
        print(f"Semgrep scan complete. Results saved to {OUTPUT_FILE}.")
    except subprocess.CalledProcessError as e:
        print(f"Error during Semgrep scan: {e}")
        # Try to save any output we got
        if e.stdout:
            try:
                with open(OUTPUT_FILE, 'wb') as f:
                    f.write(e.stdout)
                print(f"  Partial results saved to {OUTPUT_FILE}")
            except:
                pass
        return False
    except Exception as e:
        print(f"Unexpected error during Semgrep scan: {e}")
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

# Step 5: Analyze a single vulnerability with OpenAI
def analyze_vulnerability_with_ai(vulnerability):
    """Use OpenAI to analyze if a Semgrep finding is a true positive"""
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
    
    # Read FULL file content for better analysis (with context around vulnerable lines for large files)
    file_content, content_type = read_file_content(file_path, start_line, end_line)
    
    if not file_content:
        return {
            "analyzed": False,
            "error": "Could not read source code"
        }
    
    # Add line markers to highlight vulnerable section
    lines = file_content.split('\n')
    marked_content = ""
    for i, line in enumerate(lines, 1):
        if start_line <= i <= end_line:
            marked_content += f">>> LINE {i} (FLAGGED): {line}\n"
        else:
            marked_content += f"    {i}: {line}\n"
    
    # Determine what we're sending to AI
    if content_type == "full":
        code_description = f"**FULL FILE CONTENT** ({len(lines)} lines total)"
        code_to_send = marked_content
    else:
        code_description = f"**CODE CONTEXT FROM LARGE FILE**\n   - First 100 lines (imports, globals, setup)\n   - Plus ±50 lines around the vulnerability"
        code_to_send = file_content
    
    # Create prompt for OpenAI with file context
    prompt = f"""You are a security expert analyzing SAST (Static Application Security Testing) findings from Semgrep.

**Finding Details:**
- Rule ID: {check_id}
- Semgrep Severity: {severity}
- File: {file_path}
- Flagged Lines: {start_line}-{end_line}
- Semgrep Description: {message}

{code_description}
(Lines marked with >>> are flagged by Semgrep):
```
{code_to_send}
```

**Your Task:**
Analyze the code context and the specific flagged lines to determine:

1. **Is this a TRUE POSITIVE or FALSE POSITIVE?**
   - TRUE POSITIVE: Real vulnerability that can be exploited
   - FALSE POSITIVE: Safe code, sanitized input, or acceptable risk

2. **What is the ACTUAL risk level?**
   - CRITICAL: Direct exploit path, immediate danger
   - HIGH: Serious vulnerability, likely exploitable
   - MEDIUM: Vulnerability with limited impact or exploitation difficulty
   - LOW: Minor issue or requires specific conditions
   - INFO: Not a vulnerability, just informational

3. **Why?** Explain your reasoning based on:
   - Code context before and after the flagged lines
   - Input sanitization or validation present
   - How the data flows through the code
   - Security controls in place

4. **What should be done?** If true positive, provide specific fix. If false positive, explain why it's safe.

**Respond ONLY in JSON format:**
{{
  "is_vulnerable": true/false,
  "confidence": "high/medium/low",
  "risk_level": "CRITICAL/HIGH/MEDIUM/LOW/INFO",
  "reasoning": "Detailed explanation of why this is/isn't vulnerable, referencing specific code",
  "recommendation": "Specific fix or explanation of why it's a false positive"
}}"""
    
    try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specializing in code security analysis. You will receive either the full file or key sections (file header with imports/globals + vulnerability context). Analyze the provided code context to determine true vs false positives. Consider imports, variable definitions, and code flow. Respond only with valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,  # Lower temperature for more consistent analysis
            response_format={"type": "json_object"}
        )
        
        analysis = json.loads(response.choices[0].message.content)
        analysis["analyzed"] = True
        analysis["content_type"] = content_type  # Track if we analyzed full file or snippet
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
        print(f"      Found {len(files)} files in repository.")

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
