# Log Forging in indico/modules/events/timetable/operations.py:102

| Field | Value |
|---|---|
| ID | `VG-0080` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-117 |
| Rule | `Python_Log_Forging` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Log_Forging` (CWE-117) reports an issue at [`indico/modules/events/timetable/operations.py:102`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/timetable/operations.py#L102). Engine message: `Log_Forging: json at indico/modules/events/timetable/controllers/legacy.py:441 reaches info at indico/modules/events/timetable/operations.py:102`.

```py
  100      if changes:
  101          signals.event.timetable_entry_updated.send(entry, changes=changes)
  102          logger.info('Timetable entry %s updated by %s', entry, session.user)
  103          entry.event.log(EventLogRealm.management, LogKind.change, 'Timetable',
  104                          f"Entry for {object_type} '{object_title}' modified", session.user,
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/timetable/operations.py:102` and, if so, apply the standard mitigation for CWE-117.
