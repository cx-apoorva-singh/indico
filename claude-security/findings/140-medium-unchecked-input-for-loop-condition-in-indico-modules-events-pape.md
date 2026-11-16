# Unchecked Input for Loop Condition in indico/modules/events/papers/util.py:32

| Field | Value |
|---|---|
| ID | `VG-0287` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/papers/util.py:32`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/papers/util.py#L32). Engine message: `Unchecked_Input_for_Loop_Condition: with_parent at indico/modules/events/papers/util.py:23 reaches contribs at indico/modules/events/papers/util.py:32`.

```py
   30      """Get the list of contributions where user already reviewed paper."""
   31      contribs = _query_contributions_with_user_as_reviewer(event, user).all()
   32      return [contrib for contrib in contribs if contrib.paper.last_revision.has_user_reviewed(user)]
   33  
   34  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/papers/util.py:32` and, if so, apply the standard mitigation for CWE-606.
