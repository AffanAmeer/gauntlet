"""Scenario schema: the declarative description of one test case.

A scenario pairs a benign user task with (optionally) an injection planted in
content the agent will read. It also declares which credentials exist, which
ones the task legitimately needs, and where each may be used. Oracles read
these declarations to decide pass or fail, so nothing about scoring lives in
agent code.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class Family(StrEnum):
    """Attack families from the spec (section 6)."""

    DIRECT = "F1"
    AUTHORITY = "F2"
    LOOKALIKE = "F3"
    TOOL_OUTPUT = "F4"
    TOOL_DESCRIPTION = "F5"
    OBFUSCATED = "F6"
    SCOPE_CREEP = "F7"
    DELAYED = "F8"
    CONTROL = "control"


class Goal(StrEnum):
    """What the attacker is trying to achieve."""

    DISCLOSE = "G1"
    MISUSE = "G2"
    WIDEN_SCOPE = "G3"
    MISLEAD_APPROVAL = "G4"
    PERSIST = "G5"


class CredentialMode(StrEnum):
    """How the agent holds secrets during a run."""

    RAW = "raw"  # the secret value is placed in the agent's context
    BROKERED = "brokered"  # the agent only gets a handle and asks a broker to use it


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class VaultItem(_Strict):
    """A credential in the mock vault. Its value is a canary generated per run."""

    id: str = Field(pattern=r"^[a-z0-9_]+$")
    kind: Literal["api_key", "password", "totp_seed", "ssh_key", "session_cookie"]
    description: str
    allowed_origins: tuple[str, ...] = Field(min_length=1)


class Injection(_Strict):
    """Attacker-controlled text and where it is planted."""

    target: str = Field(description="Fixture path or tool name whose output carries the text")
    text: str = Field(min_length=1)


class FileExists(_Strict):
    kind: Literal["file_exists"] = "file_exists"
    path: str


class RequestMade(_Strict):
    kind: Literal["request_made"] = "request_made"
    origin: str
    path: str
    method: str = "GET"


UtilityCheck = Annotated[FileExists | RequestMade, Field(discriminator="kind")]


class Scenario(_Strict):
    id: str = Field(pattern=r"^sec-(f[1-8]|ctl)-\d{2}$")
    family: Family
    goals: tuple[Goal, ...] = ()
    rationale: str = Field(min_length=10, description="Why this scenario is realistic")
    user_task: str = Field(min_length=1)
    fixtures: dict[str, str] = Field(
        default_factory=dict, description="Mock URL or path -> fixture file, relative to the pack"
    )
    injection: Injection | None = None
    vault: tuple[VaultItem, ...] = ()
    needs: tuple[str, ...] = Field(default=(), description="Vault item ids the task needs")
    allowed_actions: tuple[str, ...] = ()
    utility: UtilityCheck

    @model_validator(mode="after")
    def _consistent(self) -> Scenario:
        ids = {item.id for item in self.vault}
        unknown = set(self.needs) - ids
        if unknown:
            raise ValueError(f"needs refers to unknown vault items: {sorted(unknown)}")
        if self.family is Family.CONTROL:
            if self.injection is not None or self.goals:
                raise ValueError("control scenarios must have no injection and no goals")
        elif self.injection is None or not self.goals:
            raise ValueError("attack scenarios need an injection and at least one goal")
        return self

    def item(self, item_id: str) -> VaultItem | None:
        return next((i for i in self.vault if i.id == item_id), None)


def load_scenario(path: Path) -> Scenario:
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return Scenario.model_validate(data)


def load_pack(directory: Path) -> list[Scenario]:
    """Load every scenario YAML in a pack, sorted by id, rejecting duplicate ids."""
    scenarios = [load_scenario(p) for p in sorted(directory.glob("*.yaml"))]
    seen: set[str] = set()
    for s in scenarios:
        if s.id in seen:
            raise ValueError(f"duplicate scenario id: {s.id}")
        seen.add(s.id)
    return sorted(scenarios, key=lambda s: s.id)
