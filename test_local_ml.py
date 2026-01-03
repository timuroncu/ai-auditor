"""Test script for local ML model"""
from dotenv import load_dotenv
load_dotenv()

from local_ml_agent import predict, vote

# Test with vulnerable C code (buffer overflow)
vulnerable_code = """
#include <string.h>
void f(char *in){
  char buf[8];
  strcpy(buf, in);
}
"""

print("=" * 60)
print("Testing Local ML Model (CodeBERT Phase 2)")
print("=" * 60)
print()
print("Test 1: Vulnerable C code (buffer overflow)")
print("-" * 40)
print(vulnerable_code)
print("-" * 40)

pred, p_vuln, threshold, device = predict(vulnerable_code)
print(f"Prediction: {'VULNERABLE' if pred == 1 else 'SAFE'}")
print(f"Probability: {p_vuln:.2%}")
print(f"Threshold: {threshold}")
print(f"Device: {device}")
print()

# Test vote function
vote_result = vote(vulnerable_code)
print("Vote Result:")
for k, v in vote_result.items():
    print(f"  {k}: {v}")
print()

# Test with safe code
safe_code = """
def add(a, b):
    return a + b
"""

print("Test 2: Safe Python code (simple addition)")
print("-" * 40)
print(safe_code)
print("-" * 40)

pred2, p_vuln2, _, _ = predict(safe_code)
print(f"Prediction: {'VULNERABLE' if pred2 == 1 else 'SAFE'}")
print(f"Probability: {p_vuln2:.2%}")
print()

vote_result2 = vote(safe_code)
print("Vote Result:")
for k, v in vote_result2.items():
    print(f"  {k}: {v}")
print()

# Test with SQL injection
sql_injection_code = """
def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return db.execute(query)
"""

print("Test 3: SQL Injection vulnerability")
print("-" * 40)
print(sql_injection_code)
print("-" * 40)

pred3, p_vuln3, _, _ = predict(sql_injection_code)
print(f"Prediction: {'VULNERABLE' if pred3 == 1 else 'SAFE'}")
print(f"Probability: {p_vuln3:.2%}")
print()

vote_result3 = vote(sql_injection_code)
print("Vote Result:")
for k, v in vote_result3.items():
    print(f"  {k}: {v}")
print()

print("=" * 60)
print("Model loaded and tested successfully!")
print("=" * 60)

