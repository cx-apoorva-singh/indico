# Unchecked Input for Loop Condition in indico/modules/events/persons/controllers.py:298

| Field | Value |
|---|---|
| ID | `VG-0292` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/persons/controllers.py:298`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/persons/controllers.py#L298). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/events/persons/controllers.py:297 reaches query at indico/modules/events/persons/controllers.py:298`.

```py
  296                   .filter(EventRole.id.in_(role_ids))
  297                   .options(joinedload('members')))
  298          return itertools.chain.from_iterable(role.members for role in query)
  299  
  300  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/persons/controllers.py:298` and, if so, apply the standard mitigation for CWE-606.
