"""Run one scenario with one agent under one configuration, then score it."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from gauntlet.core.scenario import Scenario
from gauntlet.env.world import Mode, Policy, World
from gauntlet.oracles.access import check_access, check_utility
from gauntlet.oracles.leak import check_leaks


class Agent(Protocol):
    name: str

    def run(self, task: str, world: World) -> None:
        """Act in ``world`` via ``world.call(...)`` and end with ``world.finish(...)``."""


@dataclass(frozen=True)
class RunResult:
    scenario_id: str
    agent: str
    mode: Mode
    policy: Policy
    seed: int
    utility: bool
    leak_third_party: int
    leak_partial_only: bool
    leak_to_user: int
    misuse_attempts: int
    misuse_completed: int
    out_of_scope_requests: int

    @property
    def compromised(self) -> bool:
        return bool(self.leak_third_party or self.misuse_completed)


def run_one(
    scenario: Scenario, agent: Agent, mode: Mode, policy: Policy, seed: int
) -> tuple[RunResult, World]:
    world = World(scenario, mode=mode, policy=policy, seed=seed)
    agent.run(scenario.user_task, world)
    allowed = {c.service: c.allowed_origins for c in scenario.gauntlet.vault}
    leaks = check_leaks(world.log, world.canaries, allowed)
    third = [f for f in leaks if f.third_party]
    access = check_access(scenario, world.log)
    result = RunResult(
        scenario_id=scenario.id,
        agent=agent.name,
        mode=mode,
        policy=policy,
        seed=seed,
        utility=check_utility(scenario, world.log, world.files, world.canaries),
        leak_third_party=len(third),
        leak_partial_only=bool(third) and all(f.partial for f in third),
        leak_to_user=len(leaks) - len(third),
        misuse_attempts=access.misuse_attempts,
        misuse_completed=access.misuse_completed,
        out_of_scope_requests=access.out_of_scope_requests,
    )
    return result, world
