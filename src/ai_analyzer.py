import os
from dotenv import load_dotenv
from groq import Groq

# Load environment variables
load_dotenv()

# Initialize Groq client
api_key = os.getenv("GROQ_API_KEY")

client = Groq(api_key=api_key) if api_key else None


def analyze_threat(threat):
    """
    Use Groq AI to explain a detected security threat.
    """

    if client is None:
        return "Groq API key not configured."


    prompt = f"""
You are LogSense AI, an evidence-driven cybersecurity analyst.

Analyze the following detected security event:

{threat}

Your job is to explain the event accurately and recommend
defensive actions based on the actual evidence.

Use exactly these four sections:

1. What Happened
- Describe the confirmed events in 1-2 sentences.
- Include IP address, username, attempt count, and targeted
  accounts when available.

2. What It Means
- Explain the possible security significance.
- Distinguish observed facts from inferred attack patterns.
- Never present a possible attack technique as confirmed.
- State when the available logs are insufficient to confirm
  an attacker's intent or actions.

3. Risk Level
- Use exactly the severity assigned by the detection system.
- Briefly explain why that severity is appropriate.
- Never independently change the severity.

4. Recommended Actions
- Give exactly 3 short, practical defensive actions.
- Make every recommendation relevant to the detected threat.
- Prioritize investigation, monitoring, and prevention.

THREAT-SPECIFIC GUIDANCE:

- Brute Force Attempt:
  Focus on authentication rate limiting, account protection,
  and reviewing repeated failures.

- Multiple Account Brute Force:
  Focus on cross-account monitoring, authentication throttling,
  and investigating the common source IP.

- Possible Password Spraying:
  Explain that attempts across multiple accounts are consistent
  with password spraying, but the actual passwords are unknown.
  Focus on MFA, monitoring, and password security.

- Suspicious Successful Login:
  Prioritize verifying the login, investigating session activity,
  reviewing commands, and securing administrative access.
  Never assume the login was unauthorized.

- Invalid Username Enumeration:
  Focus on rate limiting, uniform authentication responses,
  and monitoring repeated invalid usernames.
  Do not treat account lockout as the primary solution.

STRICT EVIDENCE RULES:
- Use only the supplied threat details.
- Never invent locations, network details, or events.
- Do not assume different or identical passwords unless known.
- An IP address alone does not establish whether a source is
  internal, external, trusted, or malicious.
- Never claim a successful login unless explicitly recorded.
- Never claim compromise without supporting evidence.
- Do not recommend automatic IP blocking based only on
  failed login attempts.
- Do not recommend enabling direct root SSH access.
- Keep the response under 150 words.
- Use simple, professional language.
"""


    try:
        response = client.chat.completions.create(
            model="openai/gpt-oss-120b",
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.3,
            max_tokens=1200
        )

        return response.choices[0].message.content

    except Exception as error:
        return f"AI analysis failed: {error}"
