# Role Responsibilities

Fill in the names and IDs. They go into the contribution statement.

| Role | Name | Student ID | Backup |
|------|------|------------|--------|
| M1 Developer A, "Signer" | *‹name›* | *‹ID›* | M2 |
| M2 Developer B, "Verifier" | *‹name›* | *‹ID›* | M1 |
| M3 Security tester | *‹name›* | *‹ID›* | M4 |
| M4 Risk & report lead + coordinator | *‹name›* | *‹ID›* | M3 |

> **Important (academic integrity).** The first version of the code and these docs was generated with
> an AI assistant (Claude Code). That is declared in [AI_PROMPT_LOG.md](AI_PROMPT_LOG.md). The brief says that
> work produced entirely by AI with no visible group contribution fails. Each member must therefore
> **review, test, change where needed, and own** their part, and the Git history and test notes must
> show that work. The "Definition of done" items below are written so that this contribution is real
> and visible.

---

## M1: Developer A ("Signer")

**Responsibilities:** Part A (setup and keys), Part B (sign), Part D (log helper), `README.md`,
`requirements.txt`, building the source ZIP.

**Code you own** (`release_guard.py`): `cmd_setup`, `prompt_new_passphrase`, `write_new_file`,
`cmd_sign`, `load_private_key`, `build_manifest_bytes`, `log_event`, shared `sha256_file`.

**Deliverables:** working setup and sign; a log line for every attempt; README commands that work verbatim;
pinned requirements; `CIT4020_GroupXX_Source.zip` built with `git archive`.

**Depends on:** M2 (log wiring, shared `scan_payload`), M3 (bug reports), M4 (lecturer answers for the README).

**Testing / review:** fix T1, T2 and T9 defects; review M2's code once; run the automated tests before every push.

**Evidence:** your commits; the README; the ZIP checklist in [DOCUMENTATION_GUIDE.md](DOCUMENTATION_GUIDE.md) §11.

**Done when:**
- [ ] You have read every line of Parts A, B and D and can explain why it is check → ask → write, and why the manifest is serialised once.
- [ ] You can show `head -n 1` saying ENCRYPTED and identical `sha256sum` output before and after a second setup.
- [ ] Manifest hashes equal `sha256sum` run by hand; `wc -c signature.sig` is 64.
- [ ] Wrong and empty passphrases give a clear message with no traceback, and nothing is written.
- [ ] The README has been followed verbatim by someone else.
- [ ] The ZIP contains no private key (`grep -rIl "BEGIN.*PRIVATE KEY"` finds nothing but documentation).

---

## M2: Developer B ("Verifier")

**Responsibilities:** Part C: registry lookup and the five checks in order, with clear reasons; log
wiring in verify; clean-room test of the ZIP; optional fingerprint bonus (only if the freeze is clean).

**Code you own:** `cmd_verify`, `VERIFY_CHECKS`, `check_1_manifest` … `check_5_payload`,
`manifest_shape_problem`, `unsafe_path_reason`, `finish_verify`, `load_registry`, `scan_payload`.

**Deliverables:** every one of the 8 reason codes (plus `REGISTRY_ERROR`) reproducible on demand;
`ACCEPTED` printed only in `finish_verify`; the clean-room test report.

**Depends on:** M1 (signed release, log helper), M3 (bug list).

**Testing / review:** fix T3–T8 and T10 defects; review M1's code once; run the ZIP on a fresh VM/user following only the README.

**Done when:**
- [ ] For any failing test, you can say which check fired and why the earlier checks passed.
- [ ] You can explain why `publisher_id` is read before authentication and why that is safe.
- [ ] You can explain why `is True` is used, and why the registry is re-read every run.
- [ ] The clean-room test passed: `unzip` on a fresh user, follow the README, and Path A gives ACCEPTED.

---

## M3: Security tester

**Responsibilities:** `release_A` (exactly three fabricated files), the copy-per-test workflow,
the test matrix, T1–T10 dry runs then the formal run on the frozen code, screenshots, T10 design,
and recording and editing the video.

**Files:** `release_A/payload/*`, `tests/test_matrix.md`, `tests/test_workflow.md`,
`evidence/test_results.md`, `evidence/screenshots/T*/`, the video.

**Deliverables:** 10+ results rows filled in honestly; labelled screenshots; `CIT4020_GroupXX_Demo.mp4` (3:00–5:00).

**Depends on:** M1/M2 (fixes), M4 (script review, report table).

**Done when:**
- [ ] The formal run was done on the frozen commit and its hash is recorded.
- [ ] Every row has action / expected / actual / Pass-Fail / figure, and the table matches the screenshots one-to-one.
- [ ] Your T10 prediction was committed before you ran it.
- [ ] The video was checked with `ffprobe` (180–300 s) and shows all five required scenes.

---

## M4: Risk & report lead + coordinator

**Responsibilities:** lecturer questions (by Mon Nov 16), risk analysis, design section and flowchart,
reflection (collect everyone's input), PDF assembly, contribution statement, AI declaration and prompt log,
daily check-in, final submission.

**Files:** the report source, `docs/AI_PROMPT_LOG.md`, the README's lecturer-answers table.

**Deliverables:** `CIT4020_GroupXX_Report.pdf`; the submission receipt.

**Depends on:** everyone (test table from M3, design facts from M1/M2, reflection input from all).

**Done when:**
- [ ] The risk table has 4 or more threats, each with a control and an honest remaining risk.
- [ ] The flowchart was redrawn by the group and matches `VERIFY_CHECKS` in the code.
- [ ] The reflection answers all four questions in the group's own words, citing your test numbers.
- [ ] The contribution table is written from the Git log and every member has signed off.
- [ ] The AI prompt log is complete, with every prompt verbatim.

---

## Shared responsibilities (everyone)

- **Teach-backs:** each developer walks the other three through their code (20 minutes).
- **Tracing practice:** every member traces all five checks through the real code with a specific input (e.g. `scratch/release_T3`): which function runs, what it reads, which line decides, and what is printed and logged.
- **Question drills:** see [DEMO_VIDEO_GUIDE.md](DEMO_VIDEO_GUIDE.md) §5.
- **Secrets:** keep the lab passphrase out of the repo, README, chat, screenshots and video.
- **AI log:** add a row for every prompt you use.
