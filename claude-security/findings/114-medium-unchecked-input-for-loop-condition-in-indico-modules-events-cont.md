# Unchecked Input for Loop Condition in indico/modules/events/contributions/util.py:82

| Field | Value |
|---|---|
| ID | `VG-0261` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/contributions/util.py:82`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/contributions/util.py#L82). Engine message: `Unchecked_Input_for_Loop_Condition: filter at indico/modules/events/contributions/util.py:79 reaches query at indico/modules/events/contributions/util.py:82`.

```py
   80                           Event.ends_after(dt),
   81                           Event.persons.any((EventPerson.user_id == user.id) & (has_contrib | has_subcontrib))))
   82          for event in query:
   83              data[event.id].add('contributor')
   84  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/contributions/util.py:82` and, if so, apply the standard mitigation for CWE-606.
