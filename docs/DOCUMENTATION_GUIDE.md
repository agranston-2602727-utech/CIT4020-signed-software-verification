# Documentation Guide: the PDF Report, ZIP and Submission

**Owner:** M4 (with input from all) · **Rubric:** "Report", 15 marks · **A missing report fails the project.**

This is a structure and checklist, not report text. The report must describe **your** tool,
**your** test runs and **your** reflections, in your own words.

---

## 1. Required structure and page budget

| Section | Pages | Owner | Must include |
|---------|-------|-------|--------------|
| Cover (not counted) | 1 | M4 | Title, CIT4020, group number, member names and IDs, date |
| 1. Overview | 0.25 | M4 | Scenario and what the tool does |
| 2. Risk analysis | 1 | M4 + M3 | Table of 4 or more threats: threat · impact · control · remaining risk |
| 3. Design | 1.25 | M4 + M1/M2 | Flowchart of the five checks, files and keys table, design decisions |
| 4. Test results | 1 | M3 | T1–T10 table, defects found and fixed, frozen commit hash |
| 5. Reflection | ~1 | All, M4 edits | The four questions (§6) |
| 6. Contributions + AI declaration | 0.5 | M4 | Table (§7) and declaration paragraph (§8) |
| Appendix A (not counted) | as needed | M3 | Labelled screenshots in test order |
| Appendix B (counted? ask the lecturer) | ~1 | M4 | AI prompt log table |

The body is about 5 pages, which stays within 4–6 whether or not Appendix B counts.

## 2. Formatting recommendations

- 11 pt body font, 2 cm margins, numbered headings matching the section numbers above.
- Tables for the risk analysis, files/keys, results and contributions.
- Code and commands in a monospace font.
- Figure captions: "Figure T3-1: verify rejects the modified copy with HASH_MISMATCH (check 5)."

## 3. Risk analysis template

| Threat | Impact | Security control | Remaining risk |
|--------|--------|------------------|----------------|
| *e.g. Fake publisher* | *what the attacker could achieve* | *which check, which test proves it* | *what is still possible; "none" is almost never true* |

For each threat answer three questions: **What can the attacker change? Which of my checks sees it?
What can they still do?** Candidates and facts are in [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md) §5.

## 4. System design requirements

- **Flowchart:** draw it yourselves (draw.io, Mermaid, LibreOffice Draw) using decision diamonds, the reason code on each "no" branch, and `ACCEPTED` only at the end. It must match `VERIFY_CHECKS` in the code, including `REGISTRY_ERROR`. A Mermaid version that matches the code is in [SYSTEM_DESIGN.md](SYSTEM_DESIGN.md) §7 to check yours against.
- **Files and keys table:** who creates, who reads, secret?, trusted by client? Make the trust boundary explicit.
- **Design decisions:** signature format, path rule, symlink policy, multi-failure order, extra codes, passphrase minimum.

## 5. Test results table template

Record the frozen commit hash above the table.

| Test | Objective | Expected result | Actual result | Status | Evidence |
|------|-----------|-----------------|---------------|--------|----------|
| T1 | | | *from your run* | Pass / Fail | Fig. T1-1..3 |
| … | | | | | |

Then add a short paragraph on anything that failed first, what was changed, and the re-test.

## 6. Reflection: the four questions

1. What is the difference between a **hash**, a **digital signature** and a **trust decision**?
2. Why do **T3 and T5** fail for different reasons? (Name the check number each one hits, from your own output.)
3. What happens if the **private key is stolen**? (Response, prevention, what stays exposed.)
4. Why can a **signed release still contain harmful software**?

Write from your experience: what surprised you, which test made it click, what you would change.
Do not paste generic AI text. Markers look for your own evidence.

## 7. Contribution statement template

| Member | Student ID | Role | Work completed (specific, verifiable) | Evidence |
|--------|------------|------|---------------------------------------|----------|
| | | Developer A | | commit range / files |
| | | Developer B | | |
| | | Security tester | | |
| | | Risk & report lead | | |

Write it from `git log --author` and the task list, not from memory. Be accurate, not generous.
Each member signs off.

## 8. AI use declaration and prompt log

**Declaration (Section 6):** a short, honest paragraph stating which AI tools were used, for which tasks
(e.g. "the initial implementation, tests and documentation were generated with Claude Code from the
prompt in Appendix B, row 2; the group then reviewed, tested and changed …"), and pointing to Appendix B.

**Prompt log template (Appendix B):**

| # | Date · member | Prompt (verbatim) | AI tool | Purpose | How the response was verified or modified |
|---|---------------|-------------------|---------|---------|-------------------------------------------|

The working log is [AI_PROMPT_LOG.md](AI_PROMPT_LOG.md). Keep it up to date.

## 9. Screenshot appendix

- Use the order T1 → T10, with file names like `T3_01_edit.png`.
- Every figure gets a number and a one-sentence caption.
- The terminal font must be readable in the PDF (14 pt or more when captured).
- Check that no passphrase, username, home path or private key content is visible.

## 10. PDF export and review

- [ ] Export to PDF and open it: fonts embedded, figures render, tables not cut across pages.
- [ ] Body page count is 4–6 (excluding the cover and Appendix A).
- [ ] Every figure referenced in the results table exists in Appendix A.
- [ ] Group number in the title and the file name: `CIT4020_GroupXX_Report.pdf`.
- [ ] Every member has read the final version.

## 11. Source ZIP (M1 builds, M2 clean-room tests)

```bash
git status                                         # must be clean; release_A and verifier committed after the formal T2
git archive --format=zip -o CIT4020_GroupXX_Source.zip HEAD
unzip -l CIT4020_GroupXX_Source.zip                # eyeball every path
mkdir /tmp/cleanroom && cd /tmp/cleanroom && unzip ~/path/to/CIT4020_GroupXX_Source.zip
grep -rIl "BEGIN.*PRIVATE KEY" .                   # may list only docs that MENTION the header - never a .pem
ls publisher_keys/                                 # only .gitkeep
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
python3 release_guard.py verify --release release_A    # README Path A: ACCEPTED
```

**Must be in the ZIP:** `release_guard.py`, `requirements.txt`, `README.md`, signed `release_A/`,
`verifier/` (public key + registry), `tests/`, `docs/`.
**Must not be in the ZIP:** any private key, the passphrase, `.venv/`, `__pycache__/`, `scratch/` copies, `release_log.jsonl`.

## 12. Final submission checklist

- [ ] Three files named exactly `CIT4020_GroupXX_Report.pdf`, `CIT4020_GroupXX_Source.zip`, `CIT4020_GroupXX_Demo.mp4`.
- [ ] The evidence and the video match the frozen commit.
- [ ] The ZIP passed the clean-room test and contains no private key or passphrase.
- [ ] The video is 3–5 minutes, MP4, with narration and all five scenes.
- [ ] Submitted before the deadline, with a screenshot of the receipt.
