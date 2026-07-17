from openai import OpenAI

client = OpenAI()

def answer(user_input: str) -> str:
    response = client.responses.create(
        model="example-model",
        input=[{"role": "system", "content": "Use the repository skill."}, {"role": "user", "content": user_input}],
        max_output_tokens=500,
        timeout=20,
    )
    return response.output_text
