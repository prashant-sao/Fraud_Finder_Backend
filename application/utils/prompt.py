LLM_PROMPT_TEMPLATE = """
Analyze the following job posting for potential fraud indicators. 
Consider factors like:
- Unrealistic salary promises
- Urgency tactics  
- Poor grammar/spelling
- Vague job descriptions
- Unusual payment methods
- Suspicious contact information
- Work-from-home scams
- Multi-level marketing schemes

Rate the risk level as HIGH, MEDIUM, or LOW and provide detailed reasoning.

Job posting:
{text}

Risk Assessment:
"""