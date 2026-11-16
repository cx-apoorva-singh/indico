# Unchecked Input for Loop Condition in indico/modules/events/registration/controllers/display.py:287

| Field | Value |
|---|---|
| ID | `VG-0299` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/registration/controllers/display.py:287`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/controllers/display.py#L287). Engine message: `Unchecked_Input_for_Loop_Condition: signal_query at indico/modules/events/registration/controllers/display.py:199 reaches tables at indico/modules/events/registration/controllers/display.py:287`.

```py
  285                            for regform in regforms_dict.values())
  286  
  287          num_participants = sum(table['num_participants'] for table in tables)
  288  
  289          return self.view_class.render_template(
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/controllers/display.py:287` and, if so, apply the standard mitigation for CWE-606.
