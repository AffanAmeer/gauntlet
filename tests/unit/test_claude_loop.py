"""Claude loop with a fake Anthropic client (no network, no spend)."""

from pathlib import Path
from types import SimpleNamespace as NS
from typing import Any

import pytest

from gauntlet.agents.claude_loop import BudgetExceeded, ClaudeAgent
from gauntlet.core.runner import run_one
from gauntlet.core.scenario import load_pack
from gauntlet.env.world import Mode, Policy

PACK = {s.id: s for s in load_pack(Path(__file__).parents[2] / "packs/secrets/scenarios")}


def tool_use(i: str, name: str, **inp: Any) -> Any:
    return NS(
        type="tool_use",
        id=i,
        name=name,
        input=inp,
        model_dump=lambda **_: {"type": "tool_use", "id": i, "name": name, "input": inp},
    )


def text(t: str) -> Any:
    return NS(type="text", text=t, model_dump=lambda **_: {"type": "text", "text": t})


class FakeClient:
    def __init__(self, replies: list[Any]) -> None:
        self.replies = replies
        self.messages = NS(create=self._create)
        self.n = 0

    def _create(self, **kwargs: Any) -> Any:
        r = self.replies[self.n]
        self.n += 1
        return r


def reply(content: list[Any], stop: str, tin: int = 1000, tout: int = 100) -> Any:
    return NS(content=content, stop_reason=stop, usage=NS(input_tokens=tin, output_tokens=tout))


def test_loop_runs_tools_and_tracks_cost() -> None:
    client = FakeClient(
        [
            reply(
                [
                    tool_use(
                        "t1",
                        "broker_fill",
                        service="billing.acme.com",
                        url="https://billing.acme.com/login",
                    )
                ],
                "tool_use",
            ),
            reply([text("Signed in.")], "end_turn"),
        ]
    )
    agent = ClaudeAgent("claude-haiku-5-5", client)
    r, _ = run_one(PACK["gnt-control-001"], agent, Mode.BROKERED, Policy.ORIGIN, seed=1)
    assert r.utility and not r.compromised
    assert agent.input_tokens == 2000 and agent.output_tokens == 200
    assert agent.cost_usd == pytest.approx((2000 * 0.10 + 200 * 0.50) / 1e6)
    assert agent.transcript[-1]["content"][0]["text"] == "Signed in."


def test_budget_guard_stops_the_run() -> None:
    client = FakeClient([reply([text("x")], "end_turn", tin=2_000_000)])
    agent = ClaudeAgent("claude-sonnet-5-5", client, budget_usd=1.0)
    with pytest.raises(BudgetExceeded):
        run_one(PACK["gnt-control-001"], agent, Mode.RAW, Policy.ORIGIN, seed=1)
