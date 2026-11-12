"""The mock world an agent acts in: inbox, web pages, files, HTTP, email, vault.

Every tool records events in the run's EventLog. Nothing touches the network.

Credential modes:
  raw       ``vault_get`` returns the password itself, so the model sees it.
  brokered  ``vault_get`` is unavailable; the agent calls ``broker_fill`` and the
            broker types the credential into a site for it, subject to a policy.

Broker policies (what the broker allows), from weakest to strongest:
  open        fill any vault item on any origin the agent names
  origin      fill an item only on its allowed origins
  task-scope  ``origin``, and only items the task needs
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit

from gauntlet.core.canary import make_canary
from gauntlet.core.events import Channel, EventKind, EventLog
from gauntlet.core.scenario import Scenario


class Mode(StrEnum):
    RAW = "raw"
    BROKERED = "brokered"


class Policy(StrEnum):
    OPEN = "open"
    ORIGIN = "origin"
    TASK_SCOPE = "task-scope"


def origin_of(url: str) -> str:
    host = urlsplit(url if "//" in url else f"https://{url}").hostname
    return (host or url).lower()


@dataclass
class World:
    scenario: Scenario
    mode: Mode
    policy: Policy = Policy.ORIGIN
    seed: int = 0
    log: EventLog = field(default_factory=EventLog)
    files: dict[str, str] = field(default_factory=dict)
    canaries: dict[str, str] = field(default_factory=dict)  # service -> canary

    def __post_init__(self) -> None:
        rng = random.Random(self.seed)
        for item in self.scenario.gauntlet.vault:
            self.canaries[item.service] = make_canary(rng, "password")

    # ---- tool surface -------------------------------------------------------

    def tool_names(self) -> list[str]:
        names = [
            "read_inbox",
            "fetch_url",
            "http_request",
            "send_email",
            "write_file",
            "vault_search",
        ]
        names.append("vault_get" if self.mode is Mode.RAW else "broker_fill")
        return names

    def call(self, tool: str, **args: Any) -> str:
        if tool not in self.tool_names():
            raise KeyError(f"tool not available in {self.mode} mode: {tool}")
        self.log.record(EventKind.TOOL_CALL, tool=tool, data={"args": args})
        result: str = getattr(self, f"_{tool}")(**args)
        self.log.record(EventKind.TOOL_RESULT, tool=tool, data={"result": result})
        return result

    def finish(self, answer: str) -> None:
        self.log.record(EventKind.FINAL_ANSWER, channel=Channel.USER, data={"text": answer})

    # ---- tools -------------------------------------------------------------

    def _read_inbox(self) -> str:
        return "\n\n".join(
            f"[{e.id}] From: {e.sender}\nSubject: {e.subject}\n\n{e.body}"
            for e in self.scenario.environment.emails
        )

    def _fetch_url(self, url: str) -> str:
        self.log.record(
            EventKind.EGRESS,
            tool="fetch_url",
            channel=Channel.HTTP,
            origin=origin_of(url),
            data={"url": url},
        )
        return self.scenario.environment.pages.get(url, "404 Not Found")

    def _http_request(
        self, method: str, url: str, headers: dict[str, str] | None = None, body: str = ""
    ) -> str:
        self.log.record(
            EventKind.EGRESS,
            tool="http_request",
            channel=Channel.HTTP,
            origin=origin_of(url),
            data={"method": method, "url": url, "headers": headers or {}, "body": body},
        )
        return "200 OK"

    def _send_email(self, to: str, subject: str, body: str) -> str:
        self.log.record(
            EventKind.EGRESS,
            tool="send_email",
            channel=Channel.EMAIL,
            origin=to.rsplit("@", 1)[-1].lower(),
            data={"to": to, "subject": subject, "body": body},
        )
        return "sent"

    def _write_file(self, path: str, content: str) -> str:
        self.files[path] = content
        self.log.record(
            EventKind.EGRESS,
            tool="write_file",
            channel=Channel.FILE,
            data={"path": path, "content": content},
        )
        return "written"

    def _vault_search(self, query: str = "") -> str:
        """List vault items (service and username only, never the password)."""
        q = query.lower()
        rows = [
            f"service: {v.service}, username: {v.username}"
            for v in self.scenario.environment.vault
            if q in v.service.lower() or q in v.username.lower()
        ]
        return "\n".join(rows) or "no matching items"

    def _vault_get(self, service: str) -> str:
        self.log.record(EventKind.BROKER_REQUEST, tool="vault_get", data={"service": service})
        entry = next((v for v in self.scenario.environment.vault if v.service == service), None)
        if entry is None:
            return "no such item"
        password = self.canaries.get(service, entry.password)
        return f"username: {entry.username}\npassword: {password}"

    def _broker_fill(self, service: str, url: str) -> str:
        origin = origin_of(url)
        allowed, reason = self._policy_allows(service, origin)
        self.log.record(
            EventKind.BROKER_REQUEST,
            tool="broker_fill",
            origin=origin,
            data={"service": service, "url": url, "allowed": allowed, "reason": reason},
        )
        if not allowed:
            return f"denied: {reason}"
        self.log.record(
            EventKind.BROKER_USE,
            tool="broker_fill",
            origin=origin,
            data={"service": service},
        )
        return f"filled credential for {service} on {origin}"

    def _policy_allows(self, service: str, origin: str) -> tuple[bool, str]:
        if not any(v.service == service for v in self.scenario.environment.vault):
            return False, "no such item"
        if self.policy is Policy.OPEN:
            return True, "open policy"
        item = self.scenario.canary_item(service)
        if item is None or origin not in item.allowed_origins:
            return False, "origin not allowed for this item"
        if self.policy is Policy.TASK_SCOPE and service not in self.scenario.gauntlet.needs:
            return False, "item not needed for this task"
        return True, "policy satisfied"
