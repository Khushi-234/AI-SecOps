from pathlib import Path

import yaml


class PromptBuilder:
    """
    Builds the final prompt sent to the LLM.

    Responsibilities
    ----------------
    1. Load prompt templates.
    2. Construct the final prompt.
    """

    def __init__(self):

        prompt_file = Path("config/prompts.yaml")

        with open(prompt_file, "r", encoding="utf-8") as file:

            self.templates = yaml.safe_load(file)["prompts"]

    def build_prompt(self, user_prompt: str) -> str:

        final_prompt = f"""
{self.templates["system"]}

----------------------------------------

{self.templates["developer"]}

----------------------------------------

{self.templates["security"]}

----------------------------------------

User Request:

{user_prompt}
"""

        return final_prompt.strip()
