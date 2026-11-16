# Unchecked Input for Loop Condition in indico/modules/rb/operations/locations.py:45

| Field | Value |
|---|---|
| ID | `VG-0394` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/operations/locations.py:45`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/operations/locations.py#L45). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/rb/operations/locations.py:36 reaches query at indico/modules/rb/operations/locations.py:45`.

```py
   43      else:
   44          query = _query_all_locations_for_acl_check()
   45          return any(loc.can_manage(user, allow_admin=False) for loc in query)
   46  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/operations/locations.py:45` and, if so, apply the standard mitigation for CWE-606.
