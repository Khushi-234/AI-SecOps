# pyrefly: ignore [missing-import]
from groq import Groq

from config.settings import settings
from llm.base_provider import BaseLLMProvider


class GroqProvider(BaseLLMProvider):
    """
    Groq implementation of the LLM Provider.
    """

    def __init__(self):
        self.client = Groq(
            api_key=settings.GROQ_API_KEY
        )

    def generate_response(self, prompt: str) -> str:

        completion = self.client.chat.completions.create(

            model=settings.MODEL_NAME,

            temperature=settings.TEMPERATURE,

            max_completion_tokens=settings.MAX_TOKENS,

            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        return completion.choices[0].message.content
