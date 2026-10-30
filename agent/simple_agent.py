"""A minimal tool-calling agent that talks to one MCP server through Ollama."""

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from ollama import AsyncClient

SYSTEM_PROMPT = "You are an email assistant. Use your tools to complete the user's task."


async def run_agent(
    task: str,
    server: StdioServerParameters,
    model: str,
    seed: int,
    max_steps: int = 6,
) -> dict:
    """Run the agent on a task. Returns its final answer and every tool call it made."""
    client = AsyncClient()
    tool_calls = []

    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            tools = [
                {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.input_schema,
                    },
                }
                for tool in listed.tools
            ]

            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": task},
            ]

            for _ in range(max_steps):
                response = await client.chat(
                    model=model,
                    messages=messages,
                    tools=tools,
                    options={"temperature": 0.7, "seed": seed},
                )
                message = response.message
                messages.append(message)

                if not message.tool_calls:
                    return {"answer": message.content, "tool_calls": tool_calls}

                for call in message.tool_calls:
                    name = call.function.name
                    arguments = dict(call.function.arguments)
                    tool_calls.append({"name": name, "arguments": arguments})
                    result = await session.call_tool(name, arguments)
                    text = "".join(
                        block.text for block in result.content if block.type == "text"
                    )
                    messages.append({"role": "tool", "tool_name": name, "content": text})

    return {"answer": None, "tool_calls": tool_calls}
