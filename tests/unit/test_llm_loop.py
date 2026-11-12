"""The LLM loop, driven by a fake model that replays canned replies."""

import json
from pathlib import Path
from typing import Any

from gauntlet.agents.llm_loop import LLMAgent
from gauntlet.core.runner import run_one
from gauntlet.core.scenario import load_pack
from gauntlet.env.world import Mode, Policy

PACK = {s.id: s for s in load_pack(Path(__file__).parents[2] / "packs/secrets/scenarios")}


def fake_model(replies: list[dict[str, Any]]) -> Any:
    seen: list[list[dict[str, Any]]] = []

    def complete(messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
        seen.append(list(messages))
        return replies[len(seen) - 1]

    return complete, seen


def call(i: int, name: str, **args: Any) -> dict[str, Any]:
    return {
        "id": f"c{i}",
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(args)},
    }


def test_loop_executes_tool_calls_and_scores() -> None:
    complete, seen = fake_model(
        [
            {"role": "assistant", "content": None, "tool_calls": [call(1, "read_inbox")]},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    call(
                        2,
                        "broker_fill",
                        service="billing.acme.com",
                        url="https://acme-billing.co/login",
                    )
                ],
            },
            {"role": "assistant", "content": "Signed in."},
        ]
    )
    agent = LLMAgent("fake", complete)
    r, _ = run_one(PACK["gnt-lookalike-001"], agent, Mode.BROKERED, Policy.ORIGIN, seed=1)
    assert r.misuse_attempts == 1 and r.misuse_completed == 0
    assert "acme-billing.co" in seen[1][-1]["content"]  # the model saw the inbox
    assert agent.transcript[-1]["content"] == "Signed in."


def test_bad_tool_name_is_reported_to_model_not_crash() -> None:
    complete, _ = fake_model(
        [
            {"role": "assistant", "tool_calls": [call(1, "vault_get", service="billing.acme.com")]},
            {"role": "assistant", "content": "ok"},
        ]
    )
    agent = LLMAgent("fake", complete)
    run_one(PACK["gnt-control-001"], agent, Mode.BROKERED, Policy.ORIGIN, seed=1)
    assert agent.transcript[3]["content"].startswith("error:")


def test_step_limit() -> None:
    loop = [{"role": "assistant", "tool_calls": [call(i, "read_inbox")]} for i in range(5)]
    complete, _ = fake_model(loop)
    agent = LLMAgent("fake", complete, max_steps=3)
    _, world = run_one(PACK["gnt-control-001"], agent, Mode.RAW, Policy.ORIGIN, seed=1)
    assert list(world.log)[-1].data["text"] == "(step limit reached)"


def test_vault_search_lists_services_without_passwords() -> None:
    from gauntlet.env.world import World

    w = World(PACK["gnt-control-001"], mode=Mode.RAW)
    out = w.call("vault_search", query="acme")
    assert "billing.acme.com" in out and "password" not in out.lower()


def test_wrong_arguments_get_a_usage_hint() -> None:
    complete, _ = fake_model(
        [
            {"role": "assistant", "tool_calls": [call(1, "vault_get", year=2023)]},
            {"role": "assistant", "content": "ok"},
        ]
    )
    agent = LLMAgent("fake", complete)
    run_one(PACK["gnt-control-001"], agent, Mode.RAW, Policy.ORIGIN, seed=1)
    assert "Parameters for vault_get: service" in agent.transcript[3]["content"]
