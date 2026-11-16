# Log Forging in indico/modules/events/sessions/operations.py:40

| Field | Value |
|---|---|
| ID | `VG-0075` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-117 |
| Rule | `Python_Log_Forging` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Log_Forging` (CWE-117) reports an issue at [`indico/modules/events/sessions/operations.py:40`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/sessions/operations.py#L40). Engine message: `Log_Forging: args at indico/modules/events/timetable/controllers/legacy.py:128 reaches info at indico/modules/events/sessions/operations.py:40`.

```py
   38                         f'Session block "{block.title}" for session "{session_.title}" has been created', session.user,
   39                         meta={'session_block_id': block.id})
   40      logger.info('Session block %s created by %s', block, session.user)
   41      return block
   42  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/sessions/operations.py:40` and, if so, apply the standard mitigation for CWE-117.
