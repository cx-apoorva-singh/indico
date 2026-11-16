# Unchecked Input for Loop Condition in indico/modules/users/util.py:181

| Field | Value |
|---|---|
| ID | `VG-0425` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/users/util.py:181`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/users/util.py#L181). Engine message: `Unchecked_Input_for_Loop_Condition: order_by at indico/modules/users/util.py:175 reaches events at indico/modules/users/util.py:181`.

```py
  179      # Sort by 'start_dt' so that past events appear at the top and future events at the bottom
  180      events = sorted(query, key=attrgetter('start_dt'))
  181      return {event: links[event.id] for event in events}
  182  
  183  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/users/util.py:181` and, if so, apply the standard mitigation for CWE-606.
