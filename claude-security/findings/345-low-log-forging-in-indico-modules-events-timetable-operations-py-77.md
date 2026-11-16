# Log Forging in indico/modules/events/timetable/operations.py:77

| Field | Value |
|---|---|
| ID | `VG-0079` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-117 |
| Rule | `Python_Log_Forging` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Log_Forging` (CWE-117) reports an issue at [`indico/modules/events/timetable/operations.py:77`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/timetable/operations.py#L77). Engine message: `Log_Forging: args at indico/modules/events/timetable/controllers/legacy.py:128 reaches info at indico/modules/events/timetable/operations.py:77`.

```py
   75      db.session.flush()
   76      signals.event.timetable_entry_created.send(entry)
   77      logger.info('Timetable entry %s created by %s', entry, user)
   78      entry.event.log(EventLogRealm.management, LogKind.positive, 'Timetable',
   79                      f"Entry for {object_type} '{object_title}' created", user,
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/timetable/operations.py:77` and, if so, apply the standard mitigation for CWE-117.
