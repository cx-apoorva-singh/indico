# Unchecked Input for Loop Condition in indico/modules/users/export.py:212

| Field | Value |
|---|---|
| ID | `VG-0419` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/users/export.py:212`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/users/export.py#L212). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/users/export.py:211 reaches query at indico/modules/users/export.py:212`.

```py
  210               .filter(Contribution.person_links.any(ContributionPersonLink.person.has(user=user)))
  211               .all())
  212      contribution_ids = {cid for cid, in query}
  213      return (Contribution.query
  214              .options(joinedload('person_links'),
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/users/export.py:212` and, if so, apply the standard mitigation for CWE-606.
