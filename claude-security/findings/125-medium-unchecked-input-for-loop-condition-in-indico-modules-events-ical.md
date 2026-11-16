# Unchecked Input for Loop Condition in indico/modules/events/ical.py:209

| Field | Value |
|---|---|
| ID | `VG-0272` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/ical.py:209`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/ical.py#L209). Engine message: `Unchecked_Input_for_Loop_Condition: order_by at indico/modules/categories/serialize.py:49 reaches events at indico/modules/events/ical.py:209`.

```py
  207          calendar.add('method', method)
  208  
  209      for event in events:
  210          if not skip_access_check and not event.can_access(user):
  211              continue
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/ical.py:209` and, if so, apply the standard mitigation for CWE-606.
