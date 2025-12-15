#!/usr/bin/env python3
"""
Gemini Setup Helper
Lists available models and tests your API key
"""

import os
from dotenv import load_dotenv

load_dotenv()

def check_gemini_setup():
    """Check and display Gemini setup status"""
    
    print("=" * 60)
    print("🔧 Gemini API Setup Helper")
    print("=" * 60)
    
    api_key = os.getenv('GEMINI_API_KEY')
    
    # Check 1: API Key exists
    print("\n1️⃣ Checking API Key...")
    if not api_key or api_key == 'your-gemini-api-key-here':
        print("   ❌ No valid API key found\n")
        print("   📝 STEPS TO FIX:")
        print("   ├─ 1. Visit: https://makersuite.google.com/app/apikey")
        print("   ├─ 2. Sign in with Google (no credit card needed)")
        print("   ├─ 3. Click 'Create API Key'")
        print("   ├─ 4. Copy the key (starts with 'AIza')")
        print("   ├─ 5. Edit your .env file:")
        print("   │    GEMINI_API_KEY=AIzaSy...your-actual-key")
        print("   └─ 6. Run this script again\n")
        return False
    
    print(f"   ✅ API key found: {api_key[:15]}...{api_key[-8:]}")
    
    # Check 2: Library installed
    print("\n2️⃣ Checking google-generativeai library...")
    try:
        import google.generativeai as genai
        print("   ✅ Library installed")
    except ImportError:
        print("   ❌ Library not installed")
        print("   📝 FIX: pip install google-generativeai")
        return False
    
    # Check 3: List available models
    print("\n3️⃣ Connecting to Gemini API...")
    try:
        genai.configure(api_key=api_key)
        print("   ✅ API key accepted")
        
        print("\n4️⃣ Listing available models...")
        models = genai.list_models()
        
        gemini_models = []
        for model in models:
            if 'gemini' in model.name.lower() and 'generateContent' in model.supported_generation_methods:
                gemini_models.append(model.name)
                print(f"   ✅ {model.name}")
        
        if not gemini_models:
            print("   ⚠️  No Gemini models available")
            return False
        
        # Test with first available model
        print(f"\n5️⃣ Testing with {gemini_models[0]}...")
        model = genai.GenerativeModel(gemini_models[0])
        response = model.generate_content("Say 'Gemini is working!' if you can read this.")
        
        print(f"   ✅ Response received!")
        print(f"   📥 {response.text[:100]}")
        
        print("\n" + "=" * 60)
        print("🎉 SUCCESS! Your Gemini API is fully working!")
        print("=" * 60)
        print(f"\n✅ Recommended model: {gemini_models[0]}")
        print("🚀 You can now run: python ai_classifier_v2.py")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Connection failed: {str(e)}")
        print("\n   📝 TROUBLESHOOTING:")
        print("   ├─ Invalid API key → Get new one from https://makersuite.google.com/app/apikey")
        print("   ├─ Quota exceeded → Wait 24 hours or check quota at console")
        print("   ├─ Network issue → Check your internet connection")
        print("   └─ Region blocked → Try VPN or different network")
        return False

if __name__ == "__main__":
    success = check_gemini_setup()
    
    if not success:
        print("\n" + "=" * 60)
        print("⚠️  Setup incomplete - Follow the steps above")
        print("=" * 60)
    
    exit(0 if success else 1)
