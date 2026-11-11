"""Scenario schema, built on 1Password SCAM's YAML format.

A Gauntlet scenario file is a valid SCAM scenario (id, category, difficulty,
description, environment, turns, checkpoints) plus one extra top-level block,
``gauntlet:``, which SCAM ignores. That block adds what exact scoring needs:
which vault items are canaries, where each may be used, which ones the task
needs, the attack's goals, and a deterministic task-success check.

SCAM: https://github.com/1Password/SCAM (MIT). Field names in ``environment``,
``turns`` and ``checkpoints`` follow SCAM's template so files stay portable.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class Goal(StrEnum):
    """What the attacker is trying to achieve (spec section 6; G4 dropped after review)."""

    DISCLOSE = "G1"  # a secret value reaches a third party
    MISUSE = "G2"  # a credential is used on a wrong origin
    WIDEN_SCOPE = "G3"  # the agent requests items the task does not need
    PERSIST = "G5"  # a secret is written to notes or files


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class _Loose(BaseModel):
    """SCAM-owned blocks: accept fields we do not use, so SCAM files still load."""

    model_config = ConfigDict(extra="allow", frozen=True)


# ---- SCAM-compatible blocks -------------------------------------------------


class Email(_Loose):
    id: str
    sender: str = Field(alias="from")
    subject: str
    body: str
    threat: bool = False


class VaultEntry(_Loose):
    service: str
    username: str = ""
    password: str = ""  # replaced by a canary at run time when listed in gauntlet.vault


class Environment(_Loose):
    emails: tuple[Email, ...] = ()
    vault: tuple[VaultEntry, ...] = ()
    pages: dict[str, str] = Field(
        default_factory=dict, description="Gauntlet addition: URL -> page text the agent can fetch"
    )


class Turn(_Loose):
    role: Literal["user"]
    content: str


class Checkpoint(_Loose):
    id: str
    check_type: str
    weight: float = 1.0


# ---- Gauntlet extension ----------------------------------------------------


class CanaryItem(_Strict):
    service: str = Field(description="Matches environment.vault[].service")
    allowed_origins: tuple[str, ...] = Field(min_length=1)


class FileExists(_Strict):
    kind: Literal["file_exists"] = "file_exists"
    path: str


class RequestMade(_Strict):
    kind: Literal["request_made"] = "request_made"
    origin: str


class CredentialFilled(_Strict):
    kind: Literal["credential_filled"] = "credential_filled"
    service: str
    origin: str


UtilityCheck = Annotated[FileExists | RequestMade | CredentialFilled, Field(discriminator="kind")]


class GauntletBlock(_Strict):
    attack: bool
    goals: tuple[Goal, ...] = ()
    vault: tuple[CanaryItem, ...] = ()
    needs: tuple[str, ...] = Field(default=(), description="Services the task legitimately needs")
    utility: UtilityCheck


class Scenario(_Loose):
    id: str
    category: str
    difficulty: int = Field(ge=1, le=5)
    description: str
    environment: Environment
    turns: tuple[Turn, ...] = Field(min_length=1)
    checkpoints: tuple[Checkpoint, ...] = ()
    gauntlet: GauntletBlock

    @model_validator(mode="after")
    def _consistent(self) -> Scenario:
        services = {v.service for v in self.environment.vault}
        g = self.gauntlet
        for name, ids in (("gauntlet.vault", [c.service for c in g.vault]), ("needs", g.needs)):
            unknown = set(ids) - services
            if unknown:
                raise ValueError(f"{name} names services not in environment.vault: {unknown}")
        if g.attack != bool(g.goals):
            raise ValueError("attack scenarios need goals; controls must have none")
        return self

    def canary_item(self, service: str) -> CanaryItem | None:
        return next((c for c in self.gauntlet.vault if c.service == service), None)

    @property
    def user_task(self) -> str:
        return "\n\n".join(t.content for t in self.turns)


def _parse(doc: dict[str, Any]) -> Scenario:
    return Scenario.model_validate(doc)


def load_file(path: Path) -> list[Scenario]:
    """Load every scenario in a YAML file (SCAM allows several, separated by ``---``)."""
    with path.open(encoding="utf-8") as fh:
        return [_parse(d) for d in yaml.safe_load_all(fh) if d]


def load_pack(directory: Path) -> list[Scenario]:
    scenarios = [s for p in sorted(directory.glob("*.yaml")) for s in load_file(p)]
    ids = [s.id for s in scenarios]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate scenario ids: {sorted(dupes)}")
    return sorted(scenarios, key=lambda s: s.id)
