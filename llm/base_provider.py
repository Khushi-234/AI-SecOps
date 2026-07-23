from abc import ABC, abstractmethod


class BaseLLMProvider(ABC):
    """
    Abstract base class for all LLM providers.

    Every provider (Groq, OpenAI, Ollama, etc.)
    must implement generate_response().
    """

    @abstractmethod
    def generate_response(self, prompt: str) -> str:
        """
        Generate a response from the LLM.

        Args:
            prompt (str): User prompt.

        Returns:
            str: LLM response.
        """
        pass
