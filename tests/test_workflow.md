# Test Copy Workflow (M3)

The clean signed `release_A/` is **never edited after signing**. Every test that changes something
works on its own fresh copy inside `scratch/` (ignored by Git, never zipped).

## One-line copy per test

```bash
cp -a release_A scratch/release_T3     # -a keeps timestamps and permissions (needed for T9 evidence)
cp -a release_A scratch/release_T4a
cp -a release_A scratch/release_T4b
cp -a release_A scratch/release_T5
cp -a release_A scratch/release_T6
cp -a release_A scratch/release_T7
cp -a release_A scratch/release_T9
cp -a release_A scratch/release_T10a
cp -a release_A scratch/release_T10b
```

## Scratch publishers (never in the real registry)

| Purpose | Keys | Registry |
|---------|------|----------|
| T7 unknown publisher `otherpub` | `scratch/other_keys/` | `scratch/other_verifier/` |
| T10a/T10d attacker claiming `harbourview` | `scratch/attacker_keys/` | `scratch/attacker_verifier/` |

## Tests that touch real files

- **T1** creates the real keys (formal run: from a clean state, once).
- **T2** signs the real `release_A/`. Commit it afterwards.
- **T8** edits `verifier/trusted_publishers.json`. Back it up first and confirm it was restored with `cmp`.

## Is release_A still clean?

```bash
python3 release_guard.py verify --release release_A    # must say ACCEPTED at any time
git status release_A verifier                          # must show no changes after T2's commit
```

## Reset

```bash
rm -rf scratch/release_T* scratch/other_* scratch/attacker_* scratch/*.json scratch/*.orig
```
