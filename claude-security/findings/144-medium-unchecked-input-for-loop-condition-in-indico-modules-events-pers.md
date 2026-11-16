# Unchecked Input for Loop Condition in indico/modules/events/persons/controllers.py:251

| Field | Value |
|---|---|
| ID | `VG-0291` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/persons/controllers.py:251`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/persons/controllers.py#L251). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/events/persons/controllers.py:238 reaches chain at indico/modules/events/persons/controllers.py:251`.

```py
  249  
  250          num_no_account = 0
  251          for principal in itertools.chain(event_principal_query, contrib_principal_query, session_principal_query):
  252              if principal.email not in persons:
  253                  continue
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/persons/controllers.py:251` and, if so, apply the standard mitigation for CWE-606.
