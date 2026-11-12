"""Tool-use loop using the official Anthropic SDK (``pip install gauntlet[claude]``).

Same job as ``llm_loop`` (model call, tool calls, tool results, repeat, no agent
framework) but through the Anthropic Messages API. The client is injected so
tests run with a fake and never touch the network.

Cost safety: every call's token usage is added up, and the run stops with
``BudgetExceeded`` once the estimated spend passes ``budget_usd``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from gauntlet.agents.llm_loop import SYSTEM_PROMPT, TOOL_SCHEMAS
from gauntlet.env.world import World

# USD per million tokens (input, output), from Anthropic's published prices (2026-11).
PRICES: dict[str, tuple[float, float]] = {
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-opus-5-5": (4.00, 20.00),
}


class BudgetExceeded(RuntimeError):
    pass


def claude_tools(names: list[str]) -> list[dict[str, Any]]:
    return [
        {
            "name": n,
            "description": TOOL_SCHEMAS[n]["description"],
            "input_schema": {"type": "object", "properties": TOOL_SCHEMAS[n]["properties"]},
        }
        for n in names
    ]


def _plain(block: Any) -> dict[str, Any]:
    dumped: dict[str, Any] = (
        block.model_dump(exclude_none=True) if hasattr(block, "model_dump") else dict(block)
    )
    return dumped


@dataclass
class ClaudeAgent:
    name: str  # the model id, e.g. "claude-haiku-5-5"
    client: Any
    max_steps: int = 20
    max_tokens: int = 4096
    budget_usd: float = 1.0
    input_tokens: int = 0
    output_tokens: int = 0
    transcript: list[dict[str, Any]] = field(default_factory=list)

    @property
    def cost_usd(self) -> float:
        price_in, price_out = PRICES.get(self.name, (0.0, 0.0))
        return (self.input_tokens * price_in + self.output_tokens * price_out) / 1_000_000

    def run(self, task: str, world: World) -> None:
        tools = claude_tools(world.tool_names())
        messages: list[dict[str, Any]] = [{"role": "user", "content": task}]
        answer = "(step limit reached)"
        for _ in range(self.max_steps):
            response = self.client.messages.create(
                model=self.name,
                max_tokens=self.max_tokens,
                system=SYSTEM_PROMPT,
                tools=tools,
                messages=messages,
            )
            self.input_tokens += response.usage.input_tokens
            self.output_tokens += response.usage.output_tokens
            if self.cost_usd > self.budget_usd:
                raise BudgetExceeded(
                    f"estimated ${self.cost_usd:.2f} > budget ${self.budget_usd:.2f}"
                )
            messages.append({"role": "assistant", "content": response.content})
            uses = [b for b in response.content if b.type == "tool_use"]
            if response.stop_reason != "tool_use" or not uses:
                answer = "".join(b.text for b in response.content if b.type == "text")
                if response.stop_reason == "refusal":
                    answer = f"(refused) {answer}"
                break
            results = []
            for use in uses:
                try:
                    out = world.call(use.name, **use.input)
                except (KeyError, TypeError) as exc:
                    out = f"error: {exc}"
                results.append({"type": "tool_result", "tool_use_id": use.id, "content": out})
            messages.append({"role": "user", "content": results})
        self.transcript = [
            {
                "role": m["role"],
                "content": m["content"]
                if isinstance(m["content"], str)
                else [_plain(b) for b in m["content"]],
            }
            for m in messages
        ]
        world.finish(answer)
