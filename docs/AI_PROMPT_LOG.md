# AI Prompt Log (source for Report Appendix B)

The brief requires **every** AI prompt the group used, the tool, and how each response was checked or
changed. Paste prompts **verbatim**. Add one row per prompt, the day you use it. Leaving prompts out
of the log is an integrity risk.

| # | Date · member | AI tool | Prompt (verbatim, or "see Attachment n" if long) | Purpose | Response was… | How we verified / changed it |
|---|---------------|---------|--------------------------------------------------|---------|---------------|------------------------------|
| 1 | 2026-11-14 · *‹name›* | Claude | "Review the attached file, Create a complete, clearly structured project plan for a group of four members and deliver the plan as a PDF document. In the pdf build a complete guide on how to complete the assignment." | Project plan and guide | A PDF plan and guide (`CIT4020_Assignment2_Project_Plan_and_Guide.pdf`) | *‹fill in: e.g. compared against the brief line by line; what was adopted, changed or rejected›* |
| 2 | 2026-11-20 · *‹name›* | Claude Code (Claude Opus 5.5) | "MASTER PROMPT: CIT4020 – SIGNED SOFTWARE RELEASE VERIFICATION SYSTEM" (full text in Attachment 2), sent together with the guide PDF | Generate the implementation, automated tests and the docs/ guides | `release_guard.py`, `tests/`, `README.md`, `docs/*.md`, sample `release_A/payload`, `.gitignore`, `.gitattributes`, `requirements.txt` | *‹fill in honestly: who reviewed which functions; what you ran (unit tests, manual T1–T10); what you changed or rejected and why; commit hashes of your changes›* |
| 3 | | | | | | |

## Attachment 2: the master prompt (verbatim)

> *Paste the full master prompt text here exactly as it was sent (it is long, so keep it as an
> attachment rather than in the table). Keep the original in the group's shared drive too.*

## Notes for the declaration paragraph (report Section 6)

- Say plainly which parts came from AI (row 2 generated the first version of the code, tests and guides).
- Say what the group did itself: reviewing and understanding the code, running and recording T1–T10, design decisions you confirmed or changed, writing the report, risk analysis and reflection.
- Point to the Git history for evidence of your own changes.
- Reasonable uses: explaining tracebacks or library behaviour, reviewing your own code, proof-reading, brainstorming threats you then evaluate yourselves.
- Risky uses: report text generated wholesale, results you did not observe, code nobody can explain.
