import csv
from pathlib import Path

import pytest

from gauntlet import cli
from gauntlet.agents.llm_loop import LLMAgent
from gauntlet.agents.scripted import ScriptedAgent
from gauntlet.cli import write_csv
from gauntlet.core.runner import run_one
from gauntlet.core.scenario import load_pack
from gauntlet.env.world import Mode, Policy

PACK = Path(__file__).parents[2] / "packs/secrets/scenarios"


def test_csv_has_one_row_per_run(tmp_path: Path) -> None:
    rows = [
        run_one(s, ScriptedAgent("noop", []), Mode.RAW, Policy.ORIGIN, 0)[0]
        for s in load_pack(PACK)
    ]
    out = tmp_path / "r.csv"
    write_csv(rows, out)
    got = list(csv.DictReader(out.open()))
    assert len(got) == 3 and {"scenario_id", "utility", "compromised"} <= set(got[0])


def test_main_prints_tool_calls_and_saves_traces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    agent = LLMAgent("fake", lambda m, t: {"role": "assistant", "content": "nothing to do"})
    monkeypatch.setattr(cli, "build_agent", lambda args: agent)
    out = tmp_path / "r.csv"
    cli.main(["run", "--pack", str(PACK), "--out", str(out), "--traces", str(tmp_path / "t")])
    assert "tool_calls=0" in capsys.readouterr().out
    assert len(list((tmp_path / "t").glob("*.transcript.json"))) == 6
    assert len(list((tmp_path / "t").glob("*.events.jsonl"))) == 6
