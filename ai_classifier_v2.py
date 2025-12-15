#!/usr/bin/env python3
"""
AI-Powered Vulnerability Classifier (Quality Optimized)
Priority: Gemini (Quality) → Groq (Speed) → OpenAI (Alternative) → Pattern Matching (Fallback)
"""

import os
import json
import re
from typing import Dict, List, Optional, Tuple
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class AIVulnerabilityClassifier:
    """
    AI-powered security vulnerability classifier optimized for quality
    
    Provider Priority:
    1. Google Gemini (Primary - Best quality, free 15 req/min)
    2. Groq (Secondary - Ultra fast, free 30 req/min)
    3. OpenAI (Tertiary - Alternative, requires paid key)
    4. Pattern Matching (Fallback - Always available)
    """
    
    # Vulnerability categories (OWASP Top 10 + Common Issues)
    CATEGORIES = {
        "XSS": "Cross-Site Scripting",
        "SQLi": "SQL Injection",
        "AUTH": "Broken Authentication",
        "AUTHZ": "Broken Access Control",
        "CSRF": "Cross-Site Request Forgery",
        "IDOR": "Insecure Direct Object Reference",
        "SSRF": "Server-Side Request Forgery",
        "XXE": "XML External Entity",
        "RCE": "Remote Code Execution",
        "LFI_RFI": "File Inclusion",
        "CRYPTO": "Cryptographic Failures",
        "CONFIG": "Security Misconfiguration",
        "SENSITIVE": "Sensitive Data Exposure",
        "REDIRECT": "Open Redirect",
        "HEADER": "Missing Security Headers",
        "INJECTION": "Injection Vulnerabilities",
        "DESERIALIZATION": "Insecure Deserialization",
        "COMPONENTS": "Vulnerable Components",
        "LOGGING": "Security Logging Failures",
        "OTHER": "Other Security Issues"
    }
    
    def __init__(self):
        """
        Initialize AI classifier with quality-optimized provider priority
        """
        # Provider clients
        self.gemini_model = None
        self.groq_client = None
        self.openai_client = None
        
        # Initialize providers in priority order
        self._init_gemini()     # Primary: Quality
        self._init_groq()       # Secondary: Speed
        self._init_openai()     # Tertiary: Alternative
        
        # Log available providers
        self._log_provider_status()
    
    def _init_gemini(self):
        """Initialize Google Gemini (Primary - Quality Optimized)"""
        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key:
            return
        
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            # Using gemini-2.0-flash - free tier, fast and capable
            self.gemini_model = genai.GenerativeModel('gemini-2.0-flash')
            print("✅ Google Gemini initialized (Primary provider)")
        except ImportError:
            print("⚠️  google-generativeai not installed. Run: pip install google-generativeai")
        except Exception as e:
            print(f"⚠️  Gemini initialization failed: {e}")
    
    def _init_groq(self):
        """Initialize Groq (Secondary - Speed Optimized)"""
        api_key = os.getenv('GROQ_API_KEY')
        if not api_key:
            return
        
        try:
            from groq import Groq
            self.groq_client = Groq(api_key=api_key)
            print("✅ Groq initialized (Secondary provider)")
        except ImportError:
            print("⚠️  groq not installed. Run: pip install groq")
        except Exception as e:
            print(f"⚠️  Groq initialization failed: {e}")
    
    def _init_openai(self):
        """Initialize OpenAI (Tertiary - Alternative)"""
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            return
        
        try:
            import openai
            self.openai_client = openai.OpenAI(api_key=api_key)
            print("✅ OpenAI initialized (Tertiary provider)")
        except ImportError:
            print("⚠️  openai not installed. Run: pip install openai")
        except Exception as e:
            print(f"⚠️  OpenAI initialization failed: {e}")
    
    def _log_provider_status(self):
        """Log which providers are available"""
        providers = []
        if self.gemini_model:
            providers.append("Gemini (Primary)")
        if self.groq_client:
            providers.append("Groq (Secondary)")
        if self.openai_client:
            providers.append("OpenAI (Tertiary)")
        
        if providers:
            print(f"🤖 AI Providers: {', '.join(providers)}")
        else:
            print("⚠️  No AI providers available - using pattern matching only")
    
    def classify_vulnerability(self, vulnerability: Dict) -> Dict:
        """
        Classify a vulnerability using best available AI provider
        
        Args:
            vulnerability: Dict with 'name', 'description', 'solution', etc.
            
        Returns:
            Dict with classification results including category, severity, confidence
        """
        # Try providers in priority order
        result = None
        
        # Priority 1: Gemini (Quality)
        if self.gemini_model:
            try:
                result = self._classify_with_gemini(vulnerability)
                if result:
                    result['provider'] = 'gemini'
                    return result
            except Exception as e:
                print(f"⚠️  Gemini classification failed: {e}")
        
        # Priority 2: Groq (Speed)
        if self.groq_client:
            try:
                result = self._classify_with_groq(vulnerability)
                if result:
                    result['provider'] = 'groq'
                    return result
            except Exception as e:
                print(f"⚠️  Groq classification failed: {e}")
        
        # Priority 3: OpenAI (Alternative)
        if self.openai_client:
            try:
                result = self._classify_with_openai(vulnerability)
                if result:
                    result['provider'] = 'openai'
                    return result
            except Exception as e:
                print(f"⚠️  OpenAI classification failed: {e}")
        
        # Fallback: Pattern matching
        result = self._classify_with_patterns(vulnerability)
        result['provider'] = 'pattern_matching'
        return result
    
    def _classify_with_gemini(self, vulnerability: Dict) -> Optional[Dict]:
        """Classify using Google Gemini (Highest Quality)"""
        prompt = self._build_classification_prompt(vulnerability)
        
        response = self.gemini_model.generate_content(prompt)
        return self._parse_ai_response(response.text, vulnerability)
    
    def _classify_with_groq(self, vulnerability: Dict) -> Optional[Dict]:
        """Classify using Groq (Fastest)"""
        prompt = self._build_classification_prompt(vulnerability)
        
        response = self.groq_client.chat.completions.create(
            model="llama-3.1-70b-versatile",  # Best quality model on Groq
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=500
        )
        
        return self._parse_ai_response(response.choices[0].message.content, vulnerability)
    
    def _classify_with_openai(self, vulnerability: Dict) -> Optional[Dict]:
        """Classify using OpenAI"""
        prompt = self._build_classification_prompt(vulnerability)
        
        response = self.openai_client.chat.completions.create(
            model="gpt-4o-mini",  # Cost-effective model
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=500
        )
        
        return self._parse_ai_response(response.choices[0].message.content, vulnerability)
    
    def _build_classification_prompt(self, vulnerability: Dict) -> str:
        """Build optimized prompt for vulnerability classification"""
        name = vulnerability.get('name', 'Unknown')
        desc = vulnerability.get('description', '')
        solution = vulnerability.get('solution', '')
        confidence = vulnerability.get('confidence', '')
        
        categories_list = ', '.join(self.CATEGORIES.keys())
        
        prompt = f"""Analyze this security vulnerability and provide classification:

Vulnerability Name: {name}
Description: {desc[:500]}
Confidence: {confidence}

Available Categories: {categories_list}

Provide your analysis in this EXACT JSON format:
{{
    "category": "PRIMARY_CATEGORY",
    "secondary_categories": ["RELATED_CAT1", "RELATED_CAT2"],
    "severity_score": 8.5,
    "confidence": "high",
    "attack_vector": "network/local/physical",
    "exploitability": "easy/medium/hard",
    "false_positive_likelihood": "low/medium/high",
    "business_impact": "Brief impact description",
    "technical_details": "Key technical insight",
    "remediation_priority": "critical/high/medium/low"
}}

Be precise and use ONLY the categories from the list above."""
        
        return prompt
    
    def _parse_ai_response(self, response_text: str, vulnerability: Dict) -> Dict:
        """Parse and validate AI response"""
        try:
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                classification = json.loads(json_match.group())
                
                # Validate and enrich
                classification['vulnerability_name'] = vulnerability.get('name')
                classification['original_risk'] = vulnerability.get('risk', 'Unknown')
                
                # Ensure required fields
                if 'category' not in classification:
                    classification['category'] = 'OTHER'
                if 'severity_score' not in classification:
                    classification['severity_score'] = self._default_severity(vulnerability)
                
                return classification
        except Exception as e:
            print(f"⚠️  Failed to parse AI response: {e}")
        
        return None
    
    def _classify_with_patterns(self, vulnerability: Dict) -> Dict:
        """Fallback pattern-based classification (Always available)"""
        name = vulnerability.get('name', '').lower()
        desc = vulnerability.get('description', '').lower()
        combined = f"{name} {desc}"
        
        # Pattern matching rules
        category = 'OTHER'
        confidence = 'medium'
        
        if any(x in combined for x in ['xss', 'cross-site scripting', 'script injection']):
            category = 'XSS'
            confidence = 'high'
        elif any(x in combined for x in ['sql injection', 'sqli', 'sql query']):
            category = 'SQLi'
            confidence = 'high'
        elif any(x in combined for x in ['csrf', 'cross-site request forgery']):
            category = 'CSRF'
            confidence = 'high'
        elif any(x in combined for x in ['authentication', 'login', 'session']):
            category = 'AUTH'
            confidence = 'medium'
        elif any(x in combined for x in ['authorization', 'access control', 'privilege']):
            category = 'AUTHZ'
            confidence = 'medium'
        elif any(x in combined for x in ['redirect', 'url redirection']):
            category = 'REDIRECT'
            confidence = 'high'
        elif any(x in combined for x in ['header', 'x-frame-options', 'csp', 'content-security']):
            category = 'HEADER'
            confidence = 'high'
        elif any(x in combined for x in ['crypto', 'encryption', 'tls', 'ssl']):
            category = 'CRYPTO'
            confidence = 'medium'
        elif any(x in combined for x in ['sensitive', 'exposure', 'information disclosure']):
            category = 'SENSITIVE'
            confidence = 'medium'
        elif any(x in combined for x in ['configuration', 'misconfigur']):
            category = 'CONFIG'
            confidence = 'medium'
        
        return {
            'category': category,
            'category_name': self.CATEGORIES.get(category, 'Other'),
            'confidence': confidence,
            'severity_score': self._default_severity(vulnerability),
            'provider': 'pattern_matching',
            'vulnerability_name': vulnerability.get('name'),
            'original_risk': vulnerability.get('risk', 'Unknown'),
            'false_positive_likelihood': 'low',
            'remediation_priority': self._map_priority(vulnerability.get('risk', 'Medium'))
        }
    
    def _default_severity(self, vulnerability: Dict) -> float:
        """Calculate default severity score"""
        risk_map = {
            'High': 8.0,
            'Medium': 5.0,
            'Low': 3.0,
            'Informational': 1.0
        }
        risk = vulnerability.get('risk', 'Medium')
        return risk_map.get(risk, 5.0)
    
    def _map_priority(self, risk: str) -> str:
        """Map risk to remediation priority"""
        priority_map = {
            'High': 'critical',
            'Medium': 'high',
            'Low': 'medium',
            'Informational': 'low'
        }
        return priority_map.get(risk, 'medium')
    
    def bulk_classify(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Classify multiple vulnerabilities efficiently
        
        Args:
            vulnerabilities: List of vulnerability dicts
            
        Returns:
            List of classified vulnerabilities
        """
        results = []
        total = len(vulnerabilities)
        
        print(f"\n🔍 Classifying {total} vulnerabilities...")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            try:
                classification = self.classify_vulnerability(vuln)
                results.append(classification)
                
                if i % 5 == 0:
                    print(f"   Progress: {i}/{total} ({i*100//total}%)")
            except Exception as e:
                print(f"⚠️  Failed to classify vulnerability {i}: {e}")
                # Add basic classification on failure
                results.append(self._classify_with_patterns(vuln))
        
        print(f"✅ Classification complete: {len(results)}/{total}")
        return results


# Test function
def test_classifier():
    """Test the AI classifier with sample data"""
    print("🧪 Testing AI Vulnerability Classifier\n")
    
    # Sample vulnerabilities
    test_vulns = [
        {
            "name": "Cross Site Scripting (Reflected)",
            "description": "User input is echoed back in the response without proper encoding",
            "risk": "High",
            "confidence": "Medium"
        },
        {
            "name": "SQL Injection",
            "description": "Application is vulnerable to SQL injection attacks",
            "risk": "High",
            "confidence": "High"
        },
        {
            "name": "Missing Anti-clickjacking Header",
            "description": "X-Frame-Options header is not set",
            "risk": "Medium",
            "confidence": "Medium"
        }
    ]
    
    classifier = AIVulnerabilityClassifier()
    
    print("\n" + "="*50)
    for vuln in test_vulns:
        print(f"\n📋 Vulnerability: {vuln['name']}")
        classification = classifier.classify_vulnerability(vuln)
        print(f"   Category: {classification.get('category')}")
        print(f"   Severity: {classification.get('severity_score')}")
        print(f"   Provider: {classification.get('provider')}")
        print(f"   Confidence: {classification.get('confidence')}")
    
    print("\n" + "="*50)
    print("✅ Test complete!")


if __name__ == "__main__":
    test_classifier()
