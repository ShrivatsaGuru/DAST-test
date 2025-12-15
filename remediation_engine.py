#!/usr/bin/env python3
"""
AI-Powered Remediation Engine
Generates intelligent fix suggestions for security vulnerabilities using AI
"""

import os
import json
from typing import Dict, List, Optional
from dotenv import load_dotenv

load_dotenv()


class RemediationEngine:
    """
    AI-powered engine that generates specific remediation guidance and code fixes
    """
    
    def __init__(self):
        """Initialize the remediation engine with AI provider"""
        self.gemini_model = None
        self._init_gemini()
        
        # Remediation templates by category
        self.remediation_templates = {
            'XSS': {
                'quick_fix': 'Encode user input before displaying it in HTML',
                'priority': 'critical',
                'effort': 'low'
            },
            'SQLi': {
                'quick_fix': 'Use parameterized queries instead of string concatenation',
                'priority': 'critical',
                'effort': 'medium'
            },
            'CSRF': {
                'quick_fix': 'Implement CSRF tokens for state-changing operations',
                'priority': 'high',
                'effort': 'medium'
            },
            'AUTH': {
                'quick_fix': 'Implement proper authentication mechanisms',
                'priority': 'critical',
                'effort': 'high'
            },
            'HEADER': {
                'quick_fix': 'Add security headers to HTTP responses',
                'priority': 'medium',
                'effort': 'low'
            },
            'REDIRECT': {
                'quick_fix': 'Validate and whitelist redirect URLs',
                'priority': 'high',
                'effort': 'low'
            },
            'CRYPTO': {
                'quick_fix': 'Use modern cryptographic algorithms and libraries',
                'priority': 'high',
                'effort': 'medium'
            },
            'SENSITIVE': {
                'quick_fix': 'Remove sensitive data from responses',
                'priority': 'high',
                'effort': 'low'
            }
        }
    
    def _init_gemini(self):
        """Initialize Gemini for remediation suggestions"""
        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key or api_key == 'your-gemini-api-key-here':
            print("⚠️  No Gemini API key - using template-based remediation only")
            return
        
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            self.gemini_model = genai.GenerativeModel('gemini-2.0-flash')
            print("✅ Gemini AI initialized for remediation guidance")
        except Exception as e:
            print(f"⚠️  Gemini initialization failed: {e}")
    
    def generate_remediation(self, vulnerability: Dict, language: str = "javascript") -> Dict:
        """
        Generate comprehensive remediation guidance for a vulnerability
        
        Args:
            vulnerability: Vulnerability details including name, description, category
            language: Programming language of the vulnerable code
            
        Returns:
            Dict with remediation guidance, code examples, and steps
        """
        vuln_name = vulnerability.get('name', 'Unknown')
        vuln_desc = vulnerability.get('description', '')
        vuln_category = vulnerability.get('ai_category', 'OTHER')
        solution = vulnerability.get('solution', '')
        
        print(f"🔧 Generating remediation for: {vuln_name}")
        
        # Try AI-powered remediation first
        if self.gemini_model:
            try:
                ai_remediation = self._generate_ai_remediation(
                    vuln_name, vuln_desc, solution, vuln_category, language
                )
                if ai_remediation:
                    return ai_remediation
            except Exception as e:
                print(f"⚠️  AI remediation failed: {e}, falling back to templates")
        
        # Fallback to template-based remediation
        return self._generate_template_remediation(vulnerability, language)
    
    def _generate_ai_remediation(self, vuln_name: str, vuln_desc: str, 
                                 solution: str, category: str, language: str) -> Optional[Dict]:
        """Generate AI-powered remediation using Gemini"""
        
        prompt = f"""You are a security expert helping developers fix vulnerabilities.

Vulnerability: {vuln_name}
Category: {category}
Description: {vuln_desc[:300]}
Language: {language}

Provide a comprehensive remediation guide in JSON format:

{{
    "summary": "One-line summary of the fix",
    "priority": "critical/high/medium/low",
    "effort": "low/medium/high",
    "steps": [
        "Step 1: Specific action to take",
        "Step 2: Next action",
        "Step 3: Final action"
    ],
    "code_before": "// Vulnerable code example in {language}",
    "code_after": "// Fixed code example in {language}",
    "explanation": "Why this fix works (2-3 sentences)",
    "references": [
        "https://link-to-owasp-or-documentation"
    ],
    "testing": "How to verify the fix works"
}}

Be specific, practical, and provide actual code examples in {language}.
"""
        
        try:
            response = self.gemini_model.generate_content(prompt)
            text = response.text.strip()
            
            # Extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', text, re.DOTALL)
            if json_match:
                remediation = json.loads(json_match.group())
                remediation['ai_generated'] = True
                return remediation
        except Exception as e:
            print(f"   ⚠️  Failed to parse AI response: {e}")
        
        return None
    
    def _generate_template_remediation(self, vulnerability: Dict, language: str) -> Dict:
        """Generate template-based remediation"""
        
        category = vulnerability.get('ai_category', 'OTHER')
        template = self.remediation_templates.get(category, {
            'quick_fix': 'Review and fix the security issue',
            'priority': 'medium',
            'effort': 'medium'
        })
        
        # Language-specific code examples
        code_examples = self._get_code_examples(category, language)
        
        return {
            'summary': template['quick_fix'],
            'priority': template['priority'],
            'effort': template['effort'],
            'steps': self._get_remediation_steps(category),
            'code_before': code_examples.get('before', '// Vulnerable code'),
            'code_after': code_examples.get('after', '// Fixed code'),
            'explanation': self._get_explanation(category),
            'references': self._get_references(category),
            'testing': self._get_testing_guide(category),
            'ai_generated': False
        }
    
    def _get_code_examples(self, category: str, language: str) -> Dict[str, str]:
        """Get code examples by category and language"""
        
        examples = {
            'XSS': {
                'javascript': {
                    'before': '// Vulnerable: Direct HTML injection\napp.get(\'/search\', (req, res) => {\n    const query = req.query.q;\n    res.send(`<h1>Results for: ${query}</h1>`);\n});',
                    'after': '// Fixed: Proper HTML encoding\nconst escapeHtml = require(\'escape-html\');\napp.get(\'/search\', (req, res) => {\n    const query = escapeHtml(req.query.q);\n    res.send(`<h1>Results for: ${query}</h1>`);\n});'
                },
                'python': {
                    'before': '# Vulnerable: Direct HTML injection\n@app.route(\'/search\')\ndef search():\n    query = request.args.get(\'q\', \'\')\n    return f\'<h1>Results for: {query}</h1>\'',
                    'after': '# Fixed: Proper HTML escaping\nfrom markupsafe import escape\n@app.route(\'/search\')\ndef search():\n    query = escape(request.args.get(\'q\', \'\'))\n    return f\'<h1>Results for: {query}</h1>\''
                }
            },
            'SQLi': {
                'javascript': {
                    'before': '// Vulnerable: String concatenation\napp.get(\'/user\', (req, res) => {\n    const id = req.query.id;\n    db.query(`SELECT * FROM users WHERE id = ${id}`, (err, results) => {\n        res.json(results);\n    });\n});',
                    'after': '// Fixed: Parameterized query\napp.get(\'/user\', (req, res) => {\n    const id = req.query.id;\n    db.query(\'SELECT * FROM users WHERE id = ?\', [id], (err, results) => {\n        res.json(results);\n    });\n});'
                },
                'python': {
                    'before': '# Vulnerable: String formatting\n@app.route(\'/user\')\ndef get_user():\n    user_id = request.args.get(\'id\')\n    query = f"SELECT * FROM users WHERE id = {user_id}"\n    cursor.execute(query)',
                    'after': '# Fixed: Parameterized query\n@app.route(\'/user\')\ndef get_user():\n    user_id = request.args.get(\'id\')\n    query = "SELECT * FROM users WHERE id = ?"\n    cursor.execute(query, (user_id,))'
                }
            },
            'HEADER': {
                'javascript': {
                    'before': '// Vulnerable: Missing security headers\napp.get(\'/\', (req, res) => {\n    res.send(\'<h1>Welcome</h1>\');\n});',
                    'after': '// Fixed: Security headers added\nconst helmet = require(\'helmet\');\napp.use(helmet());\napp.get(\'/\', (req, res) => {\n    res.send(\'<h1>Welcome</h1>\');\n});'
                }
            }
        }
        
        lang_examples = examples.get(category, {}).get(language.lower(), {})
        if not lang_examples:
            # Return generic example
            lang_examples = examples.get(category, {}).get('javascript', {
                'before': '// Vulnerable code example not available',
                'after': '// Fixed code example not available'
            })
        
        return lang_examples
    
    def _get_remediation_steps(self, category: str) -> List[str]:
        """Get step-by-step remediation instructions"""
        
        steps_map = {
            'XSS': [
                "Identify all user input points that are rendered in HTML",
                "Implement context-appropriate output encoding (HTML, JavaScript, URL)",
                "Use a template engine with auto-escaping enabled",
                "Implement Content Security Policy (CSP) headers",
                "Test with XSS payloads to verify fixes"
            ],
            'SQLi': [
                "Replace all dynamic SQL queries with parameterized queries",
                "Use ORM frameworks when possible",
                "Implement input validation for expected data types",
                "Apply principle of least privilege to database accounts",
                "Enable database query logging and monitoring"
            ],
            'HEADER': [
                "Install security headers middleware (helmet.js, django-cors-headers)",
                "Configure X-Frame-Options to prevent clickjacking",
                "Set X-Content-Type-Options to nosniff",
                "Add Content-Security-Policy header",
                "Test headers using security scanning tools"
            ],
            'REDIRECT': [
                "Create a whitelist of allowed redirect URLs/domains",
                "Validate all redirect parameters against whitelist",
                "Use indirect references instead of full URLs",
                "Log all redirect attempts for monitoring",
                "Show warning page for external redirects"
            ]
        }
        
        return steps_map.get(category, [
            "Review the vulnerability details carefully",
            "Implement the recommended fix from security documentation",
            "Test the fix in a staging environment",
            "Deploy to production after verification"
        ])
    
    def _get_explanation(self, category: str) -> str:
        """Get explanation of why the fix works"""
        
        explanations = {
            'XSS': "Output encoding converts special characters to their HTML entity equivalents, preventing browsers from interpreting user input as executable code. This breaks the XSS attack vector while preserving the intended display of user content.",
            'SQLi': "Parameterized queries separate SQL code from data, ensuring user input is treated as data values rather than executable SQL commands. The database driver handles proper escaping automatically.",
            'HEADER': "Security headers instruct browsers to enable built-in security features that protect against common attacks. They provide defense-in-depth even if other vulnerabilities exist.",
            'REDIRECT': "Validating redirect destinations against a whitelist prevents attackers from using your application to redirect users to malicious sites, protecting against phishing attacks."
        }
        
        return explanations.get(category, "This fix addresses the root cause of the vulnerability by implementing security best practices.")
    
    def _get_references(self, category: str) -> List[str]:
        """Get reference links for remediation"""
        
        references = {
            'XSS': [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
            ],
            'SQLi': [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
            ],
            'HEADER': [
                "https://owasp.org/www-project-secure-headers/",
                "https://securityheaders.com/"
            ],
            'REDIRECT': [
                "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
            ]
        }
        
        return references.get(category, [
            "https://owasp.org/www-project-top-ten/",
            "https://cwe.mitre.org/"
        ])
    
    def _get_testing_guide(self, category: str) -> str:
        """Get testing guidance for the fix"""
        
        testing = {
            'XSS': "Test with payloads like <script>alert('XSS')</script>, verify they display as text. Use browser dev tools to confirm no script execution.",
            'SQLi': "Try SQL injection payloads like ' OR '1'='1. Verify they return no unauthorized data. Check database logs for malformed queries.",
            'HEADER': "Use online tools like securityheaders.com to verify headers. Check browser dev tools Network tab for correct header values.",
            'REDIRECT': "Attempt to redirect to an external malicious URL. Verify it's blocked or shows a warning."
        }
        
        return testing.get(category, "Test the fix in a staging environment before deploying to production. Verify the vulnerability is no longer exploitable.")
    
    def generate_bulk_remediation(self, vulnerabilities: List[Dict], language: str = "javascript") -> List[Dict]:
        """
        Generate remediation guidance for multiple vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerability dicts
            language: Programming language
            
        Returns:
            List of remediation guidance dicts
        """
        print(f"\n🔧 Generating remediation guidance for {len(vulnerabilities)} vulnerabilities...")
        
        remediations = []
        for i, vuln in enumerate(vulnerabilities, 1):
            try:
                remediation = self.generate_remediation(vuln, language)
                remediation['vulnerability_name'] = vuln.get('name')
                remediations.append(remediation)
                
                if i % 3 == 0:
                    print(f"   Progress: {i}/{len(vulnerabilities)}")
            except Exception as e:
                print(f"   ⚠️  Failed to generate remediation for vulnerability {i}: {e}")
        
        print(f"✅ Generated {len(remediations)} remediation guides")
        return remediations


def test_remediation_engine():
    """Test the remediation engine"""
    print("🧪 Testing AI-Powered Remediation Engine\n")
    
    # Sample vulnerabilities
    test_vulns = [
        {
            'name': 'Cross Site Scripting (Reflected)',
            'description': 'User input is reflected without encoding',
            'ai_category': 'XSS',
            'solution': 'Encode output'
        },
        {
            'name': 'SQL Injection',
            'description': 'SQL queries use string concatenation',
            'ai_category': 'SQLi',
            'solution': 'Use parameterized queries'
        }
    ]
    
    engine = RemediationEngine()
    
    print("=" * 60)
    for vuln in test_vulns:
        print(f"\n📋 Vulnerability: {vuln['name']}")
        remediation = engine.generate_remediation(vuln, language="javascript")
        
        print(f"   Summary: {remediation['summary']}")
        print(f"   Priority: {remediation['priority']} | Effort: {remediation['effort']}")
        print(f"   AI Generated: {remediation.get('ai_generated', False)}")
        print(f"\n   Steps:")
        for step in remediation.get('steps', [])[:3]:
            print(f"      • {step}")
        
        if remediation.get('code_after'):
            print(f"\n   Code Fix Preview:")
            print(f"      {remediation['code_after'][:100]}...")
    
    print("\n" + "=" * 60)
    print("✅ Test complete!")


if __name__ == "__main__":
    test_remediation_engine()
