#!/usr/bin/env python3
import os
import sys
from dotenv import load_dotenv

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load environment variables from parent directory
env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
print(f"Loading .env from: {env_path}")
print(f".env file exists: {os.path.exists(env_path)}")

load_dotenv(env_path)

# Test environment variable loading
variables_to_test = [
    'DEMO_CLIENT_SECRET_KEY',
    'KEYN_AUTH_SERVER_URL', 
    'KEYN_DEMO_CLIENT_URL',
    'FLASK_SECRET_KEY',
    'KEYN_PROJECT_DIR'
]

print("\nEnvironment Variables Test:")
print("-" * 40)
for var in variables_to_test:
    value = os.environ.get(var, 'NOT_FOUND')
    print(f"{var}: {value}")

print("\nDirect .env file content (first 10 lines):")
print("-" * 40)
try:
    with open(env_path, 'r') as f:
        for i, line in enumerate(f):
            if i >= 10:
                break
            print(f"{i+1:2d}: {line.rstrip()}")
except Exception as e:
    print(f"Error reading .env file: {e}")
