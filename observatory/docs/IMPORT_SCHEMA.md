# Safe snapshot contract — version 1

Select a `.json` file in Data & safety. Import is explicit and memory-only. There is no HTTP ingestion endpoint. The optional local feed transports this same DTO from one deliberately prepared owner-only spool; see LOCAL_AGENT_SETUP.md. Unknown fields are rejected, including logs, prompts, memory, credentials, reasoning traces and extensible raw metadata. All strings render as text; source URLs remain inert.

The executable validation contract is `src/model.mjs`; `examples/snapshot.json` is a complete synthetic fixture and `examples/empty.json` is a minimal empty fixture. All fields below are required except `source.url`.

| Record | Fields |
| --- | --- |
| Snapshot | `schemaVersion: 1`, `title`, `capturedAt`, `tasks: []`, `decisions: []`, `evidence: []` |
| Task | `id`, `title`, `summary`, `owner`, `status`, `stage`, `progress`, `observedAt`, `source`, `blocker`, `nextStep` |
| Decision | `id`, `taskId`, `title`, `status`, `recommendation`, `rationale`, `tradeoffs`, `disagreement`, `outcome`, `observedAt`, `source` |
| Evidence | `id`, `taskId`, `title`, `result`, `observedAt`, `summary`, `source` |
| Source | `label`, `kind`, `recordId`, optional `url` |
| Progress | `null`, or `{ "completed": 2, "total": 4 }` |

## Values and bounds

- Maximum 256 KiB UTF-8 JSON; 100 tasks; 100 decisions; 200 evidence records. No nested arbitrary objects.
- IDs: 1–64 ASCII letters, digits, hyphens/underscores, starting with a letter or digit. Unique per record family; decision/evidence `taskId` must resolve.
- Titles/source labels: 1–120 characters; owner: 1–80; summaries/recommendation/rationale/tradeoffs/blocker/nextStep/outcome/disagreement: max 600. Only blocker, disagreement and outcome may be empty.
- Status: `planned | active | blocked | done | unknown`; stage: `proposed | implemented | verified`. Blocked needs a nonempty blocker. Verified needs at least one dated passed evidence record for the same task. That establishes structural consistency only.
- Task progress is `null` for unknown, or integer completed/total where 1 ≤ total ≤ 1000 and 0 ≤ completed ≤ total. It is checklist progress, not a probability or estimated completion percentage.
- Decision status: `awaiting-owner | resolved`. Resolved needs outcome text; awaiting-owner must have empty outcome. Importing an outcome never authorizes any action.
- Evidence result: `passed | failed | pending`. Passed/failed need an observation time. Pending may have a time indicating its last observation, or null.
- All timestamps use valid UTC `YYYY-MM-DDTHH:mm:ssZ`. `observedAt` may be null; capture may not be more than five minutes in the future. Observations may not follow capture. Freshness is measured against the visibly frozen demo time, or imported evaluation time. Manual imports do not poll; an explicitly connected local feed reevaluates freshness.
- Source kind: `synthetic | manual | authorized-api`. These are producer declarations, not proof of a connection or authorization. Record IDs are safe generic identifiers, not credentials or private provider handles.
- Optional URL: public-looking HTTPS only; max 240 characters; no credentials, query, fragment, explicit port, IP, encoded path or local/internal/test hostname. The app does not fetch, verify or make it clickable. Public-looking paths can still be sensitive; inspect before import.
- Known credential patterns, common hard personal identifiers and unsafe control/bidi characters are rejected. Arbitrary secrets/PII cannot be reliably detected. This is not a secret scanner or redaction service.

## Preparing a file

Author or export only public-safe task summaries and evidence summaries you are authorized to disclose. Inspect every field and URL. Exclude real private project names/paths, employment data, raw output, session transcripts, internal prompts, chain of thought, private dot memory and hidden instructions. Summarize the useful observation and its timestamp instead.

Example of an empty import:

```json
{
  "schemaVersion": 1,
  "title": "Empty synthetic snapshot",
  "capturedAt": "2026-10-01T10:00:00Z",
  "tasks": [],
  "decisions": [],
  "evidence": []
}
```

Invalid input produces a generic field/schema error and preserves the last good snapshot. Raw payload and filename are not echoed in error messages. Reset/reload discards imports; there is no export of imported data or browser persistence in this candidate.
