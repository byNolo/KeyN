#!/usr/bin/env python3
"""
Test script for KeyN email templates and inline images
Run this from the auth_server directory: python test_email_templates.py
"""

import os
import sys
from flask import Flask, render_template

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

def test_email_templates():
    """Test that email templates render correctly"""
    
    # Create a minimal Flask app for testing
    app = Flask(__name__, 
                template_folder='auth_server/app/templates',
                static_folder='auth_server/app/static')
    
    with app.app_context():
        try:
            # Test verify_email template
            print("Testing verify_email.html template...")
            html = render_template('email/verify_email.html', 
                                 username='TestUser', 
                                 link='https://example.com/verify/test-token')
            print("✓ verify_email.html template renders successfully")
            
            # Test password_reset template
            print("Testing password_reset.html template...")
            html = render_template('email/password_reset.html', 
                                 username='TestUser', 
                                 link='https://example.com/reset/test-token')
            print("✓ password_reset.html template renders successfully")
            
            # Test welcome template
            print("Testing welcome.html template...")
            html = render_template('email/welcome.html', 
                                 username='TestUser',
                                 dashboard_link='https://example.com/dashboard',
                                 help_link='https://example.com/help')
            print("✓ welcome.html template renders successfully")
            
            print("\n✅ All email templates are working correctly!")
            
        except Exception as e:
            print(f"❌ Template error: {e}")
            return False
    
    return True

def check_logo_files():
    """Check that required logo files exist"""
    print("\nChecking logo files...")
    
    logo_dir = 'auth_server/app/static/logos'
    required_files = [
        'light mode KeyN logo Transparent BG.svg',
        'favicon-light.svg'
    ]
    
    missing_files = []
    for file in required_files:
        file_path = os.path.join(logo_dir, file)
        if os.path.exists(file_path):
            print(f"✓ {file} found")
        else:
            print(f"❌ {file} missing")
            missing_files.append(file)
    
    if missing_files:
        print(f"\n⚠️  Missing logo files: {', '.join(missing_files)}")
        print("Email images may not display correctly.")
        return False
    else:
        print("\n✅ All required logo files are present!")
        return True

if __name__ == "__main__":
    print("KeyN Email Template Test")
    print("=" * 40)
    
    # Change to the script directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    template_test = test_email_templates()
    logo_test = check_logo_files()
    
    print("\n" + "=" * 40)
    if template_test and logo_test:
        print("🎉 All tests passed! Email system is ready.")
    else:
        print("⚠️  Some issues found. Please review the output above.")
