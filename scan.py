import os
import subprocess
import requests
import shutil
import json
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configuration
REPO = os.getenv("REPO", "username/repository-name")  # GitHub repo (e.g., 'octocat/Hello-World')
BRANCH = os.getenv("BRANCH", "main")  # Branch to scan (e.g., 'main' or 'master')
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "YOUR_GITHUB_TOKEN")  # Your GitHub token
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "results.json")  # Output file for vulnerabilities
TEMP_DIR = os.getenv("TEMP_DIR", "temp_repo")  # Temporary directory to clone repo into
RULES_PATH = os.getenv("RULES_PATH", "p/ci")  # Semgrep's classical ruleset for vulnerability scanning

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
    # Run semgrep using the classical ruleset 'p/ci'
    command = [
        "semgrep", 
        "--config", RULES_PATH,
        "--no-git-ignore",  # Scan all files, not just git-tracked ones
        "--output", OUTPUT_FILE, 
        "--json", 
        TEMP_DIR
    ]
    
    # Run Semgrep and capture the output
    try:
        subprocess.run(command, check=True)
        print(f"Semgrep scan complete. Results saved to {OUTPUT_FILE}.")
    except subprocess.CalledProcessError as e:
        print(f"Error during Semgrep scan: {e}")
        return False
    return True

# Step 4: Clean up the temporary files
def cleanup():
    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)
        print("Temporary files deleted.")

# Step 5: Load and display vulnerabilities from the JSON output
def load_vulnerabilities():
    with open(OUTPUT_FILE, 'r') as file:
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
        print("Fetching repository files recursively...")
        files = fetch_repo_files_recursive()
        print(f"Found {len(files)} files in repository.")

        # Download the files to the temporary directory
        print("\nDownloading files from GitHub...")
        download_files(files)

        # Run the Semgrep scan
        print("Running Semgrep scan...")
        if run_semgrep():
            # Load and print the vulnerabilities
            load_vulnerabilities()
        
    finally:
        # Cleanup temporary files
        cleanup()

# Run the main function
if __name__ == "__main__":
    main()
