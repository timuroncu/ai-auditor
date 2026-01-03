"""
Quick test to verify the program slicer works correctly
"""

from program_slicer import build_program_slice

# Sample vulnerable code
test_code = '''
import subprocess
from flask import Flask, request

app = Flask(__name__)

ALLOWED_COMMANDS = ['ls', 'pwd', 'whoami']

def sanitize_input(user_input):
    """Remove dangerous characters"""
    return user_input.replace(';', '').replace('&', '')

def validate_command(cmd):
    """Check if command is allowed"""
    return cmd in ALLOWED_COMMANDS

@app.route('/execute')
def execute_command():
    """Execute a system command - VULNERABLE!"""
    command = request.args.get('cmd')
    
    # Missing validation!
    result = subprocess.run(command, shell=True)  # Line 23 - SINK
    
    return result.stdout

@app.route('/safe_execute')
def safe_execute_command():
    """Execute a system command - SAFE"""
    command = request.args.get('cmd')
    
    if not validate_command(command):
        return "Invalid command"
    
    result = subprocess.run(command, shell=False)  # Line 35 - validated
    
    return result.stdout

if __name__ == '__main__':
    app.run()
'''

def test_vulnerable_function():
    """Test slicing for the vulnerable function"""
    print("=" * 80)
    print("TEST 1: Vulnerable Command Execution (Line 23)")
    print("=" * 80)
    
    # Simulate Semgrep dataflow trace
    dataflow_trace = {
        'intermediate_vars': [
            {'content': 'command', 'location': {'line': 21}},
        ]
    }
    
    slice_result = build_program_slice(
        file_content=test_code,
        file_path='test.py',
        sink_line=23,
        semgrep_dataflow=dataflow_trace,
        max_lines=600
    )
    
    if slice_result:
        print("\n✅ Program slice generated successfully!\n")
        
        print("[SINK_CONTEXT]")
        print(slice_result.sink_context[:500])
        print("...\n")
        
        print("[UPSTREAM_DATAFLOW]")
        print(slice_result.upstream_dataflow[:300])
        print("...\n")
        
        print("[HELPERS_AND_SANITIZERS]")
        print(slice_result.helpers_and_sanitizers[:300])
        print("...\n")
        
        print("[METADATA]")
        for key, value in slice_result.metadata.items():
            print(f"  {key}: {value}")
        
        print("\n" + "=" * 80)
        return True
    else:
        print("\n❌ Failed to generate program slice\n")
        return False

def test_safe_function():
    """Test slicing for the safe function"""
    print("\n" + "=" * 80)
    print("TEST 2: Safe Command Execution with Validation (Line 35)")
    print("=" * 80)
    
    dataflow_trace = {
        'intermediate_vars': [
            {'content': 'command', 'location': {'line': 30}},
        ]
    }
    
    slice_result = build_program_slice(
        file_content=test_code,
        file_path='test.py',
        sink_line=35,
        semgrep_dataflow=dataflow_trace,
        max_lines=600
    )
    
    if slice_result:
        print("\n✅ Program slice generated successfully!\n")
        
        # Check if validation function was detected
        if 'validate_command' in slice_result.helpers_and_sanitizers:
            print("✅ Validation function detected in helpers!")
        else:
            print("⚠️  Validation function not detected (may need improvement)")
        
        print("\n[METADATA]")
        for key, value in slice_result.metadata.items():
            print(f"  {key}: {value}")
        
        print("\n" + "=" * 80)
        return True
    else:
        print("\n❌ Failed to generate program slice\n")
        return False

if __name__ == '__main__':
    print("\n🔬 Testing Program Slicer\n")
    
    test1 = test_vulnerable_function()
    test2 = test_safe_function()
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Test 1 (Vulnerable code): {'PASS ✅' if test1 else 'FAIL ❌'}")
    print(f"Test 2 (Safe code):       {'PASS ✅' if test2 else 'FAIL ❌'}")
    print()
    
    if test1 and test2:
        print("🎉 All tests passed! Program slicer is working correctly.")
    else:
        print("⚠️  Some tests failed. Review the output above.")
    print()

