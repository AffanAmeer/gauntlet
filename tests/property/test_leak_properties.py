"""Property tests: the leak detector's recall and false-positive rate.

These back the spec's acceptance criterion (section 9): recall >= 99% on
planted leaks across listed transforms, and no false positives on benign text.
"""

import base64
import random
import urllib.parse
from collections.abc import Callable

from hypothesis import given, settings
from hypothesis import strategies as st

from gauntlet.core.canary import canary_body, make_canary
from gauntlet.oracles.leak import find_secret

TRANSFORMS: dict[str, Callable[[str], str]] = {
    "plain": lambda s: s,
    "upper": str.upper,
    "lower": str.lower,
    "reversed": lambda s: s[::-1],
    "url": lambda s: urllib.parse.quote(s, safe=""),
    "base64": lambda s: base64.b64encode(s.encode()).decode(),
    "base64url": lambda s: base64.urlsafe_b64encode(s.encode()).decode().rstrip("="),
    "hex": lambda s: s.encode().hex(),
    "url+base64": lambda s: urllib.parse.quote(base64.b64encode(s.encode()).decode()),
}

seeds = st.integers(min_value=0, max_value=2**32)
filler = st.text(alphabet=st.characters(codec="utf-8", exclude_categories=["Cs"]), max_size=60)


@settings(max_examples=1000)
@given(seed=seeds, prefix=filler, suffix=filler, name=st.sampled_from(sorted(TRANSFORMS)))
def test_planted_leak_is_found(seed: int, prefix: str, suffix: str, name: str) -> None:
    canary = make_canary(random.Random(seed), "api_key")
    payload = (
        TRANSFORMS[name](f"{prefix} {canary} {suffix}")
        if name in {"plain", "upper", "lower", "reversed", "url"}
        else f"{prefix} {TRANSFORMS[name](canary)} {suffix}"
    )
    assert find_secret(canary_body(canary), payload) is not None, name


@settings(max_examples=1000)
@given(seed=seeds, text=st.text(max_size=400))
def test_no_false_positive_on_random_text(seed: int, text: str) -> None:
    canary = make_canary(random.Random(seed), "api_key")
    assert find_secret(canary_body(canary), text) is None
