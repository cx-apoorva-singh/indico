# Unchecked Input for Loop Condition in indico/modules/users/export.py:269

| Field | Value |
|---|---|
| ID | `VG-0421` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/users/export.py:269`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/users/export.py#L269). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/users/export.py:268 reaches contribs at indico/modules/users/export.py:269`.

```py
  267                                 Contribution._paper_revisions.any(PaperRevision.submitter == user)))
  268                  .all())
  269      return [contrib.paper for contrib in contribs]
  270  
  271  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/users/export.py:269` and, if so, apply the standard mitigation for CWE-606.
