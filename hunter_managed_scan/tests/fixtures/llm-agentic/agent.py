def answer(client, user_input):
    prompt = "Use the search tool carefully: " + user_input
    return client.responses.create(model="fixture-model", input=prompt, tools=[{"type": "function"}])
