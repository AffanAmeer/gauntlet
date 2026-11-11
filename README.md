# Gauntlet

A test harness for tool-using AI agents. It answers one question with numbers:
**when a web page or tool output tries to trick an agent, how often does the agent
leak or misuse a credential, and how much does a credential broker help?**

Status: early. The scenario schema, event log and leak oracle are in place. The
mock environment, broker, agents and the secrets scenario pack come next.

All secrets used by Gauntlet are random canaries generated per run. Nothing here
talks to a real product, account or website.

## Quick start

```bash
uv sync
uv run pytest
```

## Layout

- `src/gauntlet/core/` scenario schema, event log, canary secrets
- `src/gauntlet/oracles/` pass/fail checks that read the event log (leak oracle so far)
- `packs/secrets/` the first scenario pack (in progress)
- `tests/` unit and property tests; tests never touch the network

## Credits

The task design (a benign user task paired with an injection, scored for both
utility and security) follows [AgentDojo](https://github.com/ethz-spylab/agentdojo)
(Debenedetti et al., 2024).

## License

MIT
