"""Command line: ``gauntlet run`` runs a pack against an agent and writes results.csv."""

from __future__ import annotations

import argparse
import csv
import dataclasses
from pathlib import Path

from gauntlet.agents.llm_loop import LLMAgent, http_completion
from gauntlet.core.runner import Agent, RunResult, run_one
from gauntlet.core.scenario import load_pack
from gauntlet.env.world import Mode, Policy

DEFAULT_PACK = Path("packs/secrets/scenarios")


def build_agent(args: argparse.Namespace) -> Agent:
    if args.agent == "llm":
        complete = http_completion(args.base_url, args.model, args.api_key_env)
        return LLMAgent(name=args.model, complete=complete)
    raise SystemExit(f"unknown agent: {args.agent}")


def write_csv(results: list[RunResult], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [f.name for f in dataclasses.fields(RunResult)] + ["compromised"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in results:
            w.writerow({**dataclasses.asdict(r), "compromised": r.compromised})


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="gauntlet")
    sub = p.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="run a scenario pack against an agent")
    run.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    run.add_argument("--agent", choices=["llm"], default="llm")
    run.add_argument("--base-url", default="http://localhost:11434/v1")
    run.add_argument("--model", default="llama3.1")
    run.add_argument("--api-key-env", default=None, help="env var holding the API key")
    run.add_argument("--modes", nargs="+", type=Mode, default=list(Mode))
    run.add_argument("--policies", nargs="+", type=Policy, default=[Policy.ORIGIN])
    run.add_argument("--repeats", type=int, default=1)
    run.add_argument("--out", type=Path, default=Path("runs/results.csv"))
    args = p.parse_args(argv)

    scenarios = load_pack(args.pack)
    agent = build_agent(args)
    results: list[RunResult] = []
    for s in scenarios:
        for mode in args.modes:
            # Policies only matter when a broker exists.
            policies = args.policies if mode is Mode.BROKERED else [Policy.ORIGIN]
            for policy in policies:
                for seed in range(args.repeats):
                    r, _ = run_one(s, agent, mode, policy, seed)
                    results.append(r)
                    print(
                        f"{s.id} {mode} {policy} seed={seed} "
                        f"utility={r.utility} compromised={r.compromised}"
                    )
    write_csv(results, args.out)
    print(f"wrote {len(results)} rows to {args.out}")
    return 0
