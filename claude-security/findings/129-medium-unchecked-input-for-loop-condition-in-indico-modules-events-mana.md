# Unchecked Input for Loop Condition in indico/modules/events/management/controllers/base.py:66

| Field | Value |
|---|---|
| ID | `VG-0276` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/management/controllers/base.py:66`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/management/controllers/base.py#L66). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/management/controllers/base.py:56 reaches contribution_persons at indico/modules/events/management/controllers/base.py:66`.

```py
   64          contribution_persons_dict = defaultdict(lambda: {'speaker': False, 'primary_author': False,
   65                                                           'secondary_author': False, 'not_registered': True})
   66          for contrib_person in contribution_persons:
   67              person_dict = contribution_persons_dict[contrib_person.person.identifier]
   68              person_dict['identifier'] = contrib_person.person.identifier
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/management/controllers/base.py:66` and, if so, apply the standard mitigation for CWE-606.
