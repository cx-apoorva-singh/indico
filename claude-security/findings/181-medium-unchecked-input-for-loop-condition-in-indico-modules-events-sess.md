# Unchecked Input for Loop Condition in indico/modules/events/sessions/clone.py:57

| Field | Value |
|---|---|
| ID | `VG-0328` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/sessions/clone.py:57`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/sessions/clone.py#L57). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/events/sessions/clone.py:53 reaches query at indico/modules/events/sessions/clone.py:57`.

```py
   55                            joinedload('own_room').lazyload('*'),
   56                            subqueryload('acl_entries')))
   57          for old_sess in query:
   58              sess = Session()
   59              sess.populate_from_attrs(old_sess, attrs)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/sessions/clone.py:57` and, if so, apply the standard mitigation for CWE-606.
