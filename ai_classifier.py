#!/usr/bin/env python3
"""
AI-Powered Vulnerability Classifier
Uses free AI APIs (Google Gemini, Groq) or local models for classification
"""

import os
import json
import re
from typing import Dict, List, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class VulnerabilityClassifier:
    """
    Classifies security vulnerabilities using AI/NLP
    Supports multiple free AI providers:
    - Google Gemini (Free tier)
    - Groq (Free tier - fastest)
    - Local pattern matching (fallback)
    """
    
    def __init__(self, provider: str = "auto"):
        """
        Initialize the classifier
        
        Args:
            provider: AI provider to use ('gemini', 'groq', 'local', or 'auto')
        """
        self.provider = provider
        self.gemini_client = None
        self.groq_client = None
        
        # Vulnerability categories
        self.categories = {
            "XSS": "Cross-Site Scripting",
            "SQLi": "SQL Injection",
            "AUTH": "Authentication Issues",
            "AUTHZ": "Authorization Issues",
            "CSRF": "Cross-Site Request Forgery",
            "IDOR": "Insecure Direct Object Reference",
            "SSRF": "Server-Side Request Forgery",
            "XXE": "XML External Entity",
            "RCE": "Remote Code Execution",
            "LFI": "Local File Inclusion",
            "CRYPTO": "Cryptographic Issues",
            "CONFIG": "Security Misconfiguration",
            "SENSITIVE": "Sensitive Data Exposure",
            "BROKEN_ACCESS": "Broken Access Control",
            "REDIRECT": "Open Redirect",
            "HEADER": "Missing Security Headers",
            "INJECTION": "Injection Vulnerabilities",
            "OTHER": "Other Security Issues"
        }
        
        # Initialize AI providers
        if provider in ["auto", "gemini"]:
            self._init_gemini()
        if provider in ["auto", "groq"]:
            self._init_groq()
    
    def _init_gemini(self):
        """Initialize Google Gemini (Free)"""
        try:
            import google.generativeai as genai
            api_key = os.getenv('GEMINI_API_KEY')
            if api_key:
                genai.configure(api_key=api_key)
                self.gemini_client = genai.GenerativeModel('gemini-pro')
                print("✅ Gemini API initialized (Free tier)")
        except Exception as e:
            print(f"⚠️  Gemini initialization failed: {e}")
    
    def _init_groq(self):
        """Initialize Groq (Free and fast)"""
        try:
            from groq import Groq
            api_key = os.getenv('GROQ_API_KEY')
            if api_key:
                self.groq_client = Groq(api_key=api_key)
                print("✅ Groq API initialized (Free tier)")
        except Exception as e:
            print(f"⚠️  Groq initialization failed: {e}")
    
    def classify_with_pattern_matching(self, vulnerability: Dict) -> Dict:
        """
        Fallback: Pattern-based classification (always available)
        
        Args:
            vulnerability: Vulnerability data from ZAP
            
        Returns:
            Classification results
        """
        name = vulnerability.get('name', '').lower()
        desc = vulnerability.get('description', '').lower()
        combined = f"{name} {desc}"
        
        # Pattern matching rules
        patterns = {
            "XSS": [r'xss', r'cross.*site.*script', r'script.*inject', r'javascript.*inject'],
            "SQLi": [r'sql.*inject', r'database.*inject', r'mysql', r'postgresql', r'oracle'],
            "AUTH": [r'authentication', r'login', r'password', r'credential', r'session'],
            "AUTHZ": [r'authorization', r'access.*control', r'privilege', r'permission'],
            "CSRF": [r'csrf', r'cross.*site.*request'],
            "REDIRECT": [r'redirect', r'open.*redirect', r'unvalidated.*redirect'],
            "HEADER": [r'header.*missing', r'security.*header', r'x-frame', r'csp', r'hsts'],
            "SENSITIVE": [r'sensitive.*data', r'information.*disclosure', r'exposure', r'leak'],
            "CONFIG": [r'misconfiguration', r'configuration', r'default.*setting'],
            "CRYPTO": [r'encryption', r'cryptograph', r'weak.*cipher', r'ssl', r'tls'],
            "INJECTION": [r'injection', r'command.*inject', r'code.*inject'],
        }
        
        # Find matching category
        matched_category = "OTHER"
        confidence = 0.5
        
        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, combined, re.IGNORECASE):
                    matched_category = category
                    confidence = 0.8
                    break
            if matched_category != "OTHER":
                break
        
        # Determine severity adjustment based on content
        severity_keywords = {
            'high': [r'remote.*code', r'rce', r'critical', r'authentication.*bypass'],
            'medium': [r'disclosure', r'missing.*header', r'configuration'],
            'low': [r'information', r'version.*disclosure']
        }
        
        original_severity = vulnerability.get('risk_level', 'Medium')
        adjusted_severity = original_severity
        
        return {
            'category': matched_category,
            'category_name': self.categories.get(matched_category, "Other"),
            'confidence': confidence,
            'original_severity': original_severity,
            'adjusted_severity': adjusted_severity,
            'method': 'pattern_matching',
            'explanation': f"Classified as {self.categories.get(matched_category, 'Other')} based on keyword patterns"
        }
    
    def classify_with_ai(self, vulnerability: Dict, provider: str = None) -> Optional[Dict]:
        """
        Classify using AI (Gemini or Groq)
        
        Args:
            vulnerability: Vulnerability data
            provider: Specific provider to use
            
        Returns:
            Classification results or None if failed
        """
        if provider == "gemini" or (provider is None and self.gemini_client):
            return self._classify_with_gemini(vulnerability)
        elif provider == "groq" or (provider is None and self.groq_client):
            return self._classify_with_groq(vulnerability)
        return None
    
    def _create_classification_prompt(self, vulnerability: Dict) -> str:
        """Create prompt for AI classification"""
        name = vulnerability.get('name', 'Unknown')
        desc = vulnerability.get('description', '')
        solution = vulnerability.get('solution', '')
        
        prompt = f"""Analyze this security vulnerability and provide classification:

Vulnerability Name: {name}
Description: {desc[:500]}
Solution: {solution[:300]}

Please classify this vulnerability into ONE of these categories:
{json.dumps(list(self.categories.keys()), indent=2)}

Also provide:
1. Confidence score (0.0 to 1.0)
2. Adjusted severity (High, Medium, Low, Informational)
3. Brief explanation (one sentence)

Respond in JSON format:
{{
    "category": "CATEGORY_CODE",
    "confidence": 0.95,
    "adjusted_severity": "High",
    "explanation": "Brief explanation here"
}}"""
        return prompt
    
    def _classify_with_gemini(self, vulnerability: Dict) -> Optional[Dict]:
        """Classify using Google Gemini"""
        try:
            prompt = self._create_classification_prompt(vulnerability)
            response = self.gemini_client.generate_content(prompt)
            
            # Extract JSON from response
            text = response.text.strip()
            # Remove markdown code blocks if present
            text = re.sub(r'```json\s*', '', text)
            text = re.sub(r'```\s*', '', text)
            
            result = json.loads(text)
            result['method'] = 'gemini_ai'
            result['category_name'] = self.categories.get(result['category'], 'Other')
            result['original_severity'] = vulnerability.get('risk_level', 'Medium')
            
            return result
        except Exception as e:
            print(f"⚠️  Gemini classification failed: {e}")
            return None
    
    def _classify_with_groq(self, vulnerability: Dict) -> Optional[Dict]:
        """Classify using Groq"""
        try:
            prompt = self._create_classification_prompt(vulnerability)
            
            response = self.groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",  # Free tier model
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in vulnerability classification. Always respond with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=500
            )
            
            text = response.choices[0].message.content.strip()
            # Remove markdown code blocks if present
            text = re.sub(r'```json\s*', '', text)
            text = re.sub(r'```\s*', '', text)
            
            result = json.loads(text)
            result['method'] = 'groq_ai'
            result['category_name'] = self.categories.get(result['category'], 'Other')
            result['original_severity'] = vulnerability.get('risk_level', 'Medium')
            
            return result
        except Exception as e:
            print(f"⚠️  Groq classification failed: {e}")
            return None
    
    def classify(self, vulnerability: Dict) -> Dict:
        """
        Main classification method
        Tries AI first, falls back to pattern matching
        
        Args:
            vulnerability: Vulnerability data
            
        Returns:
            Classification results
        """
        # Try AI classification first
        if self.provider != "local":
            ai_result = self.classify_with_ai(vulnerability)
            if ai_result:
                return ai_result
        
        # Fallback to pattern matching
        return self.classify_with_pattern_matching(vulnerability)
    
    def classify_batch(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Classify multiple vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerability data
            
        Returns:
            List of vulnerabilities with classification
        """
        classified = []
        
        for vuln in vulnerabilities:
            classification = self.classify(vuln)
            vuln_with_classification = {**vuln, 'classification': classification}
            classified.append(vuln_with_classification)
        
        return classified
    
    def get_statistics(self, classified_vulnerabilities: List[Dict]) -> Dict:
        """
        Generate statistics from classified vulnerabilities
        
        Args:
            classified_vulnerabilities: List of classified vulnerabilities
            
        Returns:
            Statistics dictionary
        """
        stats = {
            'total': len(classified_vulnerabilities),
            'by_category': {},
            'by_severity': {},
            'high_confidence': 0,
            'ai_classified': 0
        }
        
        for vuln in classified_vulnerabilities:
            classification = vuln.get('classification', {})
            
            # Count by category
            category = classification.get('category', 'OTHER')
            stats['by_category'][category] = stats['by_category'].get(category, 0) + 1
            
            # Count by severity
            severity = classification.get('adjusted_severity', 'Medium')
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            
            # Count high confidence
            if classification.get('confidence', 0) > 0.8:
                stats['high_confidence'] += 1
            
            # Count AI classified
            if 'ai' in classification.get('method', ''):
                stats['ai_classified'] += 1
        
        return stats


def main():
    """Test the classifier"""
    print("🤖 AI Vulnerability Classifier Test\n")
    
    # Sample vulnerability
    test_vuln = {
        'name': 'Cross Site Scripting (Reflected)',
        'description': 'Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user\'s browser instance.',
        'solution': 'Phase: Architecture and Design - Use a vetted library or framework that does not allow this weakness to occur.',
        'risk_level': 'High',
        'confidence': 'Medium'
    }
    
    # Test with auto provider selection
    classifier = VulnerabilityClassifier(provider="auto")
    
    print("📊 Testing Classification...\n")
    result = classifier.classify(test_vuln)
    
    print(f"Category: {result['category']} ({result['category_name']})")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"Severity: {result['original_severity']} → {result['adjusted_severity']}")
    print(f"Method: {result['method']}")
    print(f"Explanation: {result['explanation']}")
    
    print("\n✅ Classifier test complete!")


if __name__ == "__main__":
    main()
