# Trust Boundary Violation in Session Variables in indico/modules/events/sessions/operations.py:85

| Field | Value |
|---|---|
| ID | `VG-0170` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/sessions/operations.py:85`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/sessions/operations.py#L85). Engine message: `Trust_Boundary_Violation_in_Session_Variables: json at indico/modules/events/timetable/controllers/legacy.py:441 reaches 'session_block_id' at indico/modules/events/sessions/operations.py:85`.

```py
   83      session_block.event.log(EventLogRealm.management, LogKind.change, 'Sessions',
   84                              f'Session block "{session_block.title}" has been updated', session.user,
   85                              meta={'session_block_id': session_block.id})
   86      logger.info('Session block %s modified by %s', session_block, session.user)
   87  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/sessions/operations.py:85` and, if so, apply the standard mitigation for CWE-501.
