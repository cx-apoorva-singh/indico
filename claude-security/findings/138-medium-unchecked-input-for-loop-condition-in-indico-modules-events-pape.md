# Unchecked Input for Loop Condition in indico/modules/events/papers/models/call_for_papers.py:130

| Field | Value |
|---|---|
| ID | `VG-0285` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/papers/models/call_for_papers.py:130`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/papers/models/call_for_papers.py#L130). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/papers/models/call_for_papers.py:129 reaches user_competences at indico/modules/events/papers/models/call_for_papers.py:130`.

```py
  128                              .filter(PaperCompetence.user_id.in_(user_ids))
  129                              .all())
  130          return {competences.user_id: competences for competences in user_competences}
  131  
  132      @property
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/papers/models/call_for_papers.py:130` and, if so, apply the standard mitigation for CWE-606.
