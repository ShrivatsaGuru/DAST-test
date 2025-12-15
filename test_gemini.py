#!/usr/bin/env python3
"""
Quick test to verify Gemini API key is working
Run this after adding your GEMINI_API_KEY to .env file
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_gemini_connection():
    """Test Gemini API connection"""
    print("🔍 Testing Gemini API Setup...\n")
    
    # Check if API key exists
    api_key = os.getenv('GEMINI_API_KEY')
    
    if not api_key or api_key == 'your-gemini-api-key-here':
        print("❌ GEMINI_API_KEY not set in .env file")
        print("\n📝 To fix:")
        print("1. Get FREE key: https://makersuite.google.com/app/apikey")
        print("2. Edit .env file and replace 'your-gemini-api-key-here' with your actual key")
        print("3. Run this test again: python test_gemini.py")
        return False
    
    print(f"✅ API key found: {api_key[:20]}...{api_key[-10:]}")
    
    # Try to initialize Gemini
    try:
        import google.generativeai as genai
        print("✅ google-generativeai library installed")
    except ImportError:
        print("❌ google-generativeai not installed")
        print("\n📝 To fix: pip install google-generativeai")
        return False
    
    # Try to configure and test
    try:
        print("\n🔌 Connecting to Gemini API...")
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-2.0-flash')  # Free tier model
        
        # Simple test prompt
        print("📤 Sending test prompt...")
        response = model.generate_content("Say 'Hello from Gemini!' if you can read this.")
        
        print("✅ Connection successful!")
        print(f"📥 Response: {response.text[:100]}...\n")
        
        # Test with security classification
        print("🧪 Testing security vulnerability classification...")
        security_prompt = """Analyze this vulnerability and respond with just the category:
        
Vulnerability: Cross-Site Scripting (XSS) in search parameter
Description: User input is reflected in HTML without encoding

Choose ONE category: XSS, SQLi, AUTH, CSRF, or OTHER"""
        
        response = model.generate_content(security_prompt)
        print(f"📥 Classification: {response.text.strip()}\n")
        
        print("=" * 50)
        print("🎉 SUCCESS! Gemini API is working perfectly!")
        print("=" * 50)
        print("\n✅ You can now use AI-powered vulnerability classification")
        print("🚀 Next: Run 'python ai_classifier_v2.py' to see it in action")
        
        return True
        
    except Exception as e:
        print(f"❌ Connection failed: {str(e)}")
        print("\n📝 Possible issues:")
        print("1. API key might be invalid or expired")
        print("2. Check if you copied the entire key (starts with 'AIza')")
        print("3. Make sure you're connected to the internet")
        print("4. Verify your API key at: https://makersuite.google.com/app/apikey")
        return False

if __name__ == "__main__":
    success = test_gemini_connection()
    exit(0 if success else 1)
