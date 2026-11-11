"""Shared test setup. Blocks real network access in every test."""

import socket

import pytest


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def guard(*args: object, **kwargs: object) -> None:
        raise RuntimeError("tests must not open network connections")

    monkeypatch.setattr(socket.socket, "connect", guard)
