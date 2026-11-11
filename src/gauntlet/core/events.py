"""The event log: an append-only record of everything an agent did in a run.

Oracles only ever look at this log and the final mock state. Keeping the record
separate from scoring means an old run can be re-scored when an oracle changes.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventKind(StrEnum):
    TOOL_CALL = "tool_call"  # the agent invoked a tool
    TOOL_RESULT = "tool_result"  # what the tool returned to the agent
    EGRESS = "egress"  # data left the agent: HTTP request, email, file write, message
    BROKER_REQUEST = "broker_request"  # the agent asked the broker for a credential
    BROKER_USE = "broker_use"  # the broker used a credential on the agent's behalf
    FINAL_ANSWER = "final_answer"  # the agent's last message to the user


class Channel(StrEnum):
    """Where egressed data went. USER is the person who gave the task."""

    HTTP = "http"
    EMAIL = "email"
    FILE = "file"
    MESSAGE = "message"
    TOOL_ARG = "tool_arg"  # arguments passed to a third-party tool
    USER = "user"


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    step: int = Field(ge=0)
    kind: EventKind
    tool: str | None = None
    channel: Channel | None = None
    origin: str | None = None  # e.g. "billing.acme.com" for HTTP egress or broker use
    data: dict[str, Any] = Field(default_factory=dict)

    def text_payload(self, *, include_keys: bool = True) -> str:
        """All string content of the event, flattened, for leak scanning.

        Keys are included by default because an agent can smuggle data in a
        header or field name, not only in values.
        """
        return "\n".join(_strings(self.data, include_keys))


def _strings(value: Any, include_keys: bool) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            if include_keys:
                yield str(k)
            yield from _strings(v, include_keys)
    elif isinstance(value, list | tuple):
        for v in value:
            yield from _strings(v, include_keys)
    elif value is not None:
        yield str(value)


class EventLog:
    def __init__(self) -> None:
        self._events: list[Event] = []

    def record(self, kind: EventKind, **fields: Any) -> Event:
        event = Event(step=len(self._events), kind=kind, **fields)
        self._events.append(event)
        return event

    def __iter__(self) -> Iterator[Event]:
        return iter(self._events)

    def __len__(self) -> int:
        return len(self._events)

    def of_kind(self, *kinds: EventKind) -> list[Event]:
        return [e for e in self._events if e.kind in kinds]

    def write_jsonl(self, path: Path) -> None:
        with path.open("w", encoding="utf-8") as fh:
            for e in self._events:
                fh.write(e.model_dump_json() + "\n")

    @classmethod
    def read_jsonl(cls, path: Path) -> EventLog:
        log = cls()
        with path.open(encoding="utf-8") as fh:
            log._events = [Event.model_validate(json.loads(line)) for line in fh if line.strip()]
        return log

    @classmethod
    def from_events(cls, events: Iterable[Event]) -> EventLog:
        log = cls()
        log._events = list(events)
        return log
