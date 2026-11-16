# Trust Boundary Violation in Session Variables in indico/modules/events/timetable/controllers/legacy.py:452

| Field | Value |
|---|---|
| ID | `VG-0178` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/timetable/controllers/legacy.py:452`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/timetable/controllers/legacy.py#L452). Engine message: `Trust_Boundary_Violation_in_Session_Variables: json at indico/modules/events/timetable/controllers/legacy.py:441 reaches rv at indico/modules/events/timetable/controllers/legacy.py:452`.

```py
  450              parent_timetable_entry = self.event.timetable_entries.filter_by(id=data['parent_id']).one()
  451              move_timetable_entry(self.entry, parent=parent_timetable_entry)
  452              rv['session'] = rv['slotEntry'] = self.serializer.serialize_session_block_entry(parent_timetable_entry)
  453          elif data.get('day'):
  454              rv['old'] = self.serializer.serialize_timetable_entry(self.entry)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/timetable/controllers/legacy.py:452` and, if so, apply the standard mitigation for CWE-501.
