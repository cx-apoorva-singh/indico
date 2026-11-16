# Unchecked Input for Loop Condition in indico/modules/events/api.py:793

| Field | Value |
|---|---|
| ID | `VG-0251` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/api.py:793`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/api.py#L793). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/events/api.py:780 reaches yield_per at indico/modules/events/api.py:793`.

```py
  791              counter = 0
  792              # Query the DB in chunks of 1000 records per query until the limit is satisfied
  793              for event in query.yield_per(1000):
  794                  if event.can_access(self._user):
  795                      counter += 1
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/api.py:793` and, if so, apply the standard mitigation for CWE-606.
