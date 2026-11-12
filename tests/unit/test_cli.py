import csv
from pathlib import Path

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
