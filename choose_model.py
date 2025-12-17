import os
from dotenv import load_dotenv

load_dotenv()


LLM_PROMPT_TEMPLATE = """
You are an experienced application security engineer. Analyze the following code issue and provide a concise, actionable fix or mitigation. Your response should be clear, technically accurate, and suitable for inclusion in a professional security report.

File: {file}
Rule: {rule_id}
Description: {message}
Code Snippet:
{code}

Please provide your recommended fix or mitigation in 2-3 sentences.
"""

class GeminiResolver:
    def __init__(self):
        import google.generativeai as genai
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        self.model = genai.GenerativeModel("gemini-2.0-flash-lite")

    def get_resolution(self, issue):
        prompt = LLM_PROMPT_TEMPLATE.format(
            file=issue['file'],
            rule_id=issue['rule_id'],
            message=issue['message'],
            code=issue['code']
        )
        response = self.model.generate_content(prompt)
        return response.text.strip()

# In the future, you can add an OpenAIResolver class here with the same interface.

def get_model(provider="gemini"):
    if provider == "gemini":
        return GeminiResolver()
    # elif provider == "openai":
    #     return OpenAIResolver()
    else:
        raise ValueError(f"Unknown provider: {provider}")
