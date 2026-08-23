# CTF agent design

## Phases

1. **Inventory** — authenticate to CTFd, collect challenge metadata and files.
2. **Triage** — estimate value/minute and assign a specialist.
3. **Investigation** — run bounded, read-only local tools and record evidence.
4. **Verification** — require two independent signals before accepting a flag candidate.
5. **Submission** — disabled by default; later add an explicit approval gate.

## Throughput rules

- Never ask the model to perform work a local tool can do faster.
- Run independent challenge workers concurrently, with a hard per-challenge budget.
- Feed compact evidence summaries to the coordinator; keep raw artifacts on disk.
- Cache every download and analysis result by SHA-256.
- Prefer breadth-first discovery over deep single-problem reasoning.

## One-command operation

`scripts/ctf_autopilot.py` owns the complete loop: inventory, download, fast
scan, heuristic ranking, and parallel Codex workers. The only intentionally
separate action is flag submission, which needs candidate verification so one
bad model guess does not consume attempts.

## Specialist agents

- Web: HTTP request reproduction, parameter mapping, response comparison.
- Forensics: file signatures, metadata, carving, audio/image analysis.
- OSINT: only public sources explicitly relevant to the challenge.
- Crypto: identify encoding/cipher families before attempting cracking.
- Reverse: static inspection first, then controlled execution in a sandbox.

The coordinator should call specialists as tools so it retains ownership of the
queue and can stop low-yield work. Each specialist returns evidence, commands
run, confidence, and a suggested next action.
