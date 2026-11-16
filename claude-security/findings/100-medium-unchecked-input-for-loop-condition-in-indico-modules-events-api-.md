# Unchecked Input for Loop Condition in indico/modules/events/api.py:523

| Field | Value |
|---|---|
| ID | `VG-0247` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/api.py:523`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/api.py#L523). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/events/api.py:513 reaches query at indico/modules/events/api.py:523`.

```py
  521              'timetable_entry'
  522          )
  523          return self.serialize_events(x for x in query if self._filter_event(x) and x.can_access(self.user))
  524  
  525      def _filter_event(self, event):
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/api.py:523` and, if so, apply the standard mitigation for CWE-606.
