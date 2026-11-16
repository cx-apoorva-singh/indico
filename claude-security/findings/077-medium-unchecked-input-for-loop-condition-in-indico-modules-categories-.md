# Unchecked Input for Loop Condition in indico/modules/categories/models/categories.py:668

| Field | Value |
|---|---|
| ID | `VG-0224` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/categories/models/categories.py:668`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/categories/models/categories.py#L668). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/categories/models/categories.py:667 reaches hidden_events at indico/modules/categories/models/categories.py:668`.

```py
  666          from indico.modules.events import Event
  667          hidden_events = Event.query.with_parent(self).filter_by(visibility=0).all()
  668          return [event for event in hidden_events if not event.can_display(user)]
  669  
  670      @property
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/categories/models/categories.py:668` and, if so, apply the standard mitigation for CWE-606.
