# Domain docs

**Layout**: single-context (one `GLOSSARY.md` + `docs/adr/` at the repo root).

This fits almost every repo. The consumer rules for reading them are:

- `GLOSSARY.md` at the repo root contains shared terminology and glossary entries.
- ADRs (Architecture Decision Records) live in `docs/adr/` and are read in chronological order (newest first) or by tag.
- When referencing an ADR, use the format: `[[ADR-001]]` or `ADR-001` for the first decision record.