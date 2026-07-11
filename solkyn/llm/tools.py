"""Tool schema helpers for LLM function calling.

Tool schemas follow the OpenAI function-calling format, which is the de facto standard
supported by OpenAI, Anthropic (via conversion), LM Studio, Ollama, vLLM, etc.
"""

from __future__ import annotations


def make_tool_schema(name: str, description: str, parameters: dict) -> dict:
    """Create a tool schema in OpenAI function-calling format.

    Args:
        name: Tool name (e.g., 'bash_exec').
        description: What the tool does.
        parameters: JSON Schema for the tool's parameters.

    Returns:
        Tool schema dict in OpenAI format.
    """
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": parameters,
        },
    }


def build_tool_result_message(tool_call_id: str, content: str) -> dict:
    """Build a tool result message for the conversation history.

    Works with both OpenAI format (role='tool') and is converted
    to Anthropic format by LLMManager internally.
    """
    return {
        "role": "tool",
        "tool_call_id": tool_call_id,
        "content": content,
    }


def build_assistant_message_with_tool_calls(content: str | None, tool_calls: list[dict]) -> dict:
    """Build an assistant message that includes tool calls.

    This is needed to maintain conversation history — after the LLM returns
    tool calls, we must include them in the assistant message before appending
    tool results.
    """
    msg: dict = {"role": "assistant", "content": content or ""}
    if tool_calls:
        msg["tool_calls"] = [
            {
                "id": tc["id"],
                "type": "function",
                "function": {
                    "name": tc["name"],
                    "arguments": __import__("json").dumps(tc["arguments"]),
                },
            }
            for tc in tool_calls
        ]
    return msg
