# Unchecked Input for Loop Condition in indico/modules/events/persons/controllers.py:133

| Field | Value |
|---|---|
| ID | `VG-0289` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/persons/controllers.py:133`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/persons/controllers.py#L133). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/persons/controllers.py:125 reaches event_persons_query at indico/modules/events/persons/controllers.py:133`.

```py
  131  
  132          event_person_users = set()
  133          for event_person, registration in event_persons_query:
  134              data = persons[event_person.email or event_person.id]
  135              if registration and registration.is_active:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/persons/controllers.py:133` and, if so, apply the standard mitigation for CWE-606.
