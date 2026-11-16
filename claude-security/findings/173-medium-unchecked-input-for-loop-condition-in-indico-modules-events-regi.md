# Unchecked Input for Loop Condition in indico/modules/events/registration/util.py:925

| Field | Value |
|---|---|
| ID | `VG-0320` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/registration/util.py:925`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/util.py#L925). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/registration/util.py:923 reaches reg_data at indico/modules/events/registration/util.py:925`.

```py
  923                  .all())
  924      registered_user_ids = {rd.user_id for rd in reg_data if rd.user_id is not None}
  925      registered_emails = {rd.email for rd in reg_data}
  926  
  927      for row_num, record in enumerate(user_records, 1):
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/util.py:925` and, if so, apply the standard mitigation for CWE-606.
