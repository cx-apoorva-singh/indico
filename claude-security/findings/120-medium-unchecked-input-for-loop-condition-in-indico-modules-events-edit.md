# Unchecked Input for Loop Condition in indico/modules/events/editing/controllers/backend/management.py:311

| Field | Value |
|---|---|
| ID | `VG-0267` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/editing/controllers/backend/management.py:311`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/editing/controllers/backend/management.py#L311). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/editing/controllers/backend/management.py:310 reaches contribs at indico/modules/events/editing/controllers/backend/management.py:311`.

```py
  309              ~Contribution.editables.any(Editable.type == self.editable_type)
  310          ).all()
  311          for contrib in contribs:
  312              log_metadata = {'contribution_id': contrib.id}
  313              for person_link in contrib.person_links:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/editing/controllers/backend/management.py:311` and, if so, apply the standard mitigation for CWE-606.
