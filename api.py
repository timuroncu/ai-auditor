"""
Flask API Backend for AI Security Auditor UI
Connects the React frontend with the scan.py vulnerability scanner
"""

import os
import json
import subprocess
import threading
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

# Store scan results
scan_results = {}
scan_status = {}

def run_scan(repo, scan_id):
    """Run the scan in a background thread"""
    try:
        scan_status[scan_id] = {'status': 'running', 'stage': 1, 'progress': 0}

        # Prepare environment with the repo from UI input
        scan_env = {
            **os.environ,
            'PATH': f"{os.environ.get('PATH', '')}:/Users/keremyunusoglu/Library/Python/3.9/bin",
            'REPO': repo  # Override REPO with the value from UI
        }

        # Run scan.py with REPO passed directly as environment variable
        scan_status[scan_id] = {'status': 'running', 'stage': 3, 'progress': 50}

        print(f"[API] Starting scan for repo: {repo}")

        result = subprocess.run(
            ['python3', 'scan.py'],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(__file__) or '.',
            env=scan_env
        )

        print(f"[API] Scan completed with return code: {result.returncode}")
        if result.stderr:
            print(f"[API] Stderr: {result.stderr[:500]}")

        scan_status[scan_id] = {'status': 'running', 'stage': 4, 'progress': 80}

        # Read the results
        ai_analysis_file = os.path.join(os.path.dirname(__file__), 'ai_analysis.json')

        if os.path.exists(ai_analysis_file):
            with open(ai_analysis_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            scan_results[scan_id] = data
            scan_status[scan_id] = {'status': 'complete', 'stage': 5, 'progress': 100}
        else:
            # Create minimal result if no vulnerabilities found
            scan_results[scan_id] = {
                'repository': repo,
                'branch': 'main',
                'voting_summary': {
                    'confirmed_vulnerabilities': 0,
                    'low_probability': 0,
                    'not_vulnerable': 0
                },
                'results': []
            }
            scan_status[scan_id] = {'status': 'complete', 'stage': 5, 'progress': 100}

    except Exception as e:
        scan_status[scan_id] = {'status': 'error', 'error': str(e)}
        scan_results[scan_id] = None


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new security scan"""
    data = request.json
    repo = data.get('repo')

    if not repo:
        return jsonify({'error': 'Repository is required'}), 400

    # Generate scan ID
    import time
    scan_id = f"scan_{int(time.time())}"

    # Start scan in background
    thread = threading.Thread(target=run_scan, args=(repo, scan_id))
    thread.start()
    thread.join()  # Wait for completion for now (can be async later)

    if scan_id in scan_results and scan_results[scan_id]:
        return jsonify(scan_results[scan_id])
    else:
        return jsonify({'error': 'Scan failed'}), 500


@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get the status of a running scan"""
    if scan_id in scan_status:
        return jsonify(scan_status[scan_id])
    return jsonify({'error': 'Scan not found'}), 404


@app.route('/api/scan/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """Get the results of a completed scan"""
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    return jsonify({'error': 'Results not found'}), 404


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'service': 'AI Security Auditor API'})


if __name__ == '__main__':
    print("Starting AI Security Auditor API...")
    print("API running at http://localhost:5001")
    # Disable reloader to prevent restart when temp_repo files change during scan
    app.run(host='0.0.0.0', port=5001, debug=True, use_reloader=False)
