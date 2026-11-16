# Unchecked Input for Loop Condition in indico/modules/events/api.py:78

| Field | Value |
|---|---|
| ID | `VG-0245` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/api.py:78`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/api.py#L78). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/api.py:77 reaches events at indico/modules/events/api.py:78`.

```py
   76      def export_timetable(self, user):
   77          events = Event.query.filter(Event.id.in_(map(int, self._idList)), ~Event.is_deleted).all()
   78          return {event.id: self._serialize_timetable(event, user) for event in events}
   79  
   80  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/api.py:78` and, if so, apply the standard mitigation for CWE-606.
