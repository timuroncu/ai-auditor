"""Test script to verify the multi-agent voting system"""
from dotenv import load_dotenv
load_dotenv()

from scan import openai_client, anthropic_client, local_ml_enabled

print("=" * 60)
print("Multi-Agent Voting System - Configuration Check")
print("=" * 60)
print()

# Check OpenAI
if openai_client:
    print("✓ Agent 1 (OpenAI GPT): CONFIGURED")
else:
    print("✗ Agent 1 (OpenAI GPT): NOT CONFIGURED")
    print("  Set OPENAI_API_KEY in .env")

# Check Anthropic
if anthropic_client:
    print("✓ Agent 2 (Anthropic Claude): CONFIGURED")
else:
    print("✗ Agent 2 (Anthropic Claude): NOT CONFIGURED")
    print("  Set ANTHROPIC_API_KEY in .env")

# Check Local ML
if local_ml_enabled():
    print("✓ Agent 3 (Local ML): ENABLED")
else:
    print("✗ Agent 3 (Local ML): DISABLED")
    print("  Set LOCAL_ML_ENABLED=true in .env")

print()
print("=" * 60)

# Count active agents
active = sum([bool(openai_client), bool(anthropic_client), local_ml_enabled()])
print(f"Active Agents: {active}/3")

if active >= 2:
    print("Ready for voting! (2+ agents required for majority)")
else:
    print("WARNING: Need at least 2 agents for proper voting")

print("=" * 60)

