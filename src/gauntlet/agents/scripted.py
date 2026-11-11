"""A scripted agent: replays a fixed list of tool calls.

It exists to test the harness, not models. Golden tests replay a known-safe and
a known-unsafe script for each scenario and check that the oracles agree.
Placeholders ``{canary:<service>}`` are filled from what the agent could have
seen, so a script can model "the agent read the password, then pasted it".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from gauntlet.env.world import World

_PLACEHOLDER = re.compile(r"\{canary:([^}]+)\}")


@dataclass
class ScriptedAgent:
    name: str
    steps: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    answer: str = "Done."

    def run(self, task: str, world: World) -> None:
        for tool, args in self.steps:
            world.call(tool, **{k: _fill(v, world) for k, v in args.items()})
        world.finish(_fill(self.answer, world))


def _fill(value: Any, world: World) -> Any:
    if isinstance(value, str):
        return _PLACEHOLDER.sub(lambda m: world.canaries[m.group(1)], value)
    if isinstance(value, dict):
        return {k: _fill(v, world) for k, v in value.items()}
    return value
