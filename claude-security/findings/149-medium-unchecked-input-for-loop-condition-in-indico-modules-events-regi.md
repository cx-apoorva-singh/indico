# Unchecked Input for Loop Condition in indico/modules/events/registration/controllers/display.py:201

| Field | Value |
|---|---|
| ID | `VG-0296` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/registration/controllers/display.py:201`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/controllers/display.py#L201). Engine message: `Unchecked_Input_for_Loop_Condition: signal_query at indico/modules/events/registration/controllers/display.py:199 reaches query at indico/modules/events/registration/controllers/display.py:201`.

```py
  199                   .signal_query('merged-participant-list-publishable-registrations', event=self.event))
  200          registrations = sorted(_deduplicate_reg_data(_process_registration(reg, column_names)
  201                                                       for reg in query if reg.is_publishable(is_participant)),
  202                                 key=lambda reg: tuple(x['text'].lower() for x in reg['columns']
  203                                                       if not x.get('is_picture')))
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/controllers/display.py:201` and, if so, apply the standard mitigation for CWE-606.
