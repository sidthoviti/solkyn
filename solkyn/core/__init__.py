"""Core utilities — process-wide concerns (budgets, cost, time).

Imported by both the orchestrator and `LLMManager`. Keep this layer
free of project-specific imports so the orchestrator can depend on it
without circular references.
"""
