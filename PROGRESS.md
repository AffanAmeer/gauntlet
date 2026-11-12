# Progress

Last updated: 2026-11-11

## Direction (decided 2026-11-11)

Build on 1Password SCAM's YAML scenario format (credit SCAM, MIT) in this
separate repo. Add exact canary leak checks and compare credential broker
policies on task success and misuse. Fable review changes accepted: brokered
mode measures misuse attempts vs completions per policy (not "zero leaks by
construction"), pilot 3 scenarios before the full pack, task x attack design
with honest intervals, v1 cut by about a third.

## Done

- Scenario schema: SCAM-shaped YAML plus a `gauntlet:` block (canary items,
  allowed origins, needs, goals, utility check).
- Event log, canary secrets, leak oracle (plain, URL, base64, hex, reversed,
  case, partial, split) with Hypothesis property tests.
- Mock world: inbox, pages, HTTP, email, files; raw vault or broker with
  `open`, `origin`, `task-scope` policies.
- Access oracle (misuse attempts vs completed, out-of-scope requests) and
  utility oracle.
- Scripted agent and runner; 3 pilot scenarios with golden tests.
- `gauntlet run` CLI (llm agent, modes, policies, repeats) writing results.csv.
- LLM tool-use loop for any OpenAI-compatible API (Ollama works, $0), tested
  with a fake model. 27 tests pass; ruff and mypy clean.

## Next (in order, each a small commit)

1. $0 dry run with a local model: Ollama is NOT installed in the cloud sandbox, so this
   needs Affan's laptop (`ollama pull llama3.1`, then `uv run gauntlet run`) or a free API tier.
3. Paid pilot only after telling Affan the cost (cap $10 total).
4. Check SCAM's own validator accepts our files; one small PR to SCAM.
5. Grow the pack (task x attack combinations) once the pilot shows the scenarios work.

## Blocked

- GitHub repo `AffanAmeer/gauntlet` not created yet. Backup:
  `/mnt/project-files/gauntlet/gauntlet.bundle` (`git clone gauntlet.bundle gauntlet`).
