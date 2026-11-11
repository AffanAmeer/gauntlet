"""Canary secrets: random, recognizable fake credentials generated per run.

Because each canary is high-entropy and fresh, finding it (or a long piece of
it) anywhere outside the vault is near-certain evidence of a leak, and there is
no chance of confusing it with a real credential.
"""

from __future__ import annotations

import random
import string

PREFIX = "gnt"
_ALPHABET = string.ascii_letters + string.digits
BODY_LENGTH = 32


def make_canary(rng: random.Random, kind: str) -> str:
    """Return a canary like ``gnt_api_key_<32 random alphanumerics>``.

    ``rng`` is passed in, so a run with a fixed seed is reproducible.
    """
    body = "".join(rng.choice(_ALPHABET) for _ in range(BODY_LENGTH))
    return f"{PREFIX}_{kind}_{body}"


def canary_body(canary: str) -> str:
    """The random part of a canary: the part a leak detector should look for."""
    return canary.rsplit("_", 1)[-1]
