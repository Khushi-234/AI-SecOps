from llm.groq_provider import GroqProvider


def main():

    provider = GroqProvider()

    response = provider.generate_response("Say hello in one sentence.")

    print()

    print("=" * 50)

    print(response)

    print("=" * 50)


if __name__ == "__main__":
    main()
