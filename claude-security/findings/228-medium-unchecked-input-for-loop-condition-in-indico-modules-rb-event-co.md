# Unchecked Input for Loop Condition in indico/modules/rb/event/controllers.py:92

| Field | Value |
|---|---|
| ID | `VG-0375` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/event/controllers.py:92`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/event/controllers.py#L92). Engine message: `Unchecked_Input_for_Loop_Condition: order_by at indico/modules/rb/event/controllers.py:32 reaches query at indico/modules/rb/event/controllers.py:92`.

```py
   90                     'title': contrib.title,
   91                     'full_title': contrib.verbose_title}
   92                    for contrib in query]
   93          return jsonify(result)
   94  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/event/controllers.py:92` and, if so, apply the standard mitigation for CWE-606.
