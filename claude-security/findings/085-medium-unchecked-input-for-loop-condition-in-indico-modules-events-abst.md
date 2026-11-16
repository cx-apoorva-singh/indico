# Unchecked Input for Loop Condition in indico/modules/events/abstracts/controllers/abstract_list.py:243

| Field | Value |
|---|---|
| ID | `VG-0232` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/abstracts/controllers/abstract_list.py:243`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/abstracts/controllers/abstract_list.py#L243). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/abstracts/controllers/abstract_list.py:239 reaches abstract_persons at indico/modules/events/abstracts/controllers/abstract_list.py:243`.

```py
  241          abstract_persons_dict = defaultdict(lambda: {'speaker': False, 'submitter': False, 'primary_author': False,
  242                                                       'secondary_author': False})
  243          for abstract_person in abstract_persons:
  244              user_or_person = abstract_person.person.user or abstract_person.person
  245              person_dict = _get_or_create_person_dict(user_or_person)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/abstracts/controllers/abstract_list.py:243` and, if so, apply the standard mitigation for CWE-606.
