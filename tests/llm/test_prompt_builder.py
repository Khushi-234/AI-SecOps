from llm.prompt_builder import PromptBuilder


def main():

    builder = PromptBuilder()

    prompt = builder.build_prompt("Explain what Machine Learning is.")

    print()

    print("=" * 70)

    print(prompt)

    print("=" * 70)


if __name__ == "__main__":
    main()
