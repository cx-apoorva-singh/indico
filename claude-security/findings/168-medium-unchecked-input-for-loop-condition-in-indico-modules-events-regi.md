# Unchecked Input for Loop Condition in indico/modules/events/registration/util.py:639

| Field | Value |
|---|---|
| ID | `VG-0315` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/registration/util.py:639`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/util.py#L639). Engine message: `Unchecked_Input_for_Loop_Condition: join at indico/modules/events/registration/util.py:629 reaches query at indico/modules/events/registration/util.py:639`.

```py
  637          return cached_templates[regform].is_ticket and registration.is_ticket_blocked
  638  
  639      return [r for r in query if not _is_ticket_blocked(r)]
  640  
  641  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/util.py:639` and, if so, apply the standard mitigation for CWE-606.
