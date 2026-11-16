# Unchecked Input for Loop Condition in indico/modules/events/management/controllers/cloning.py:192

| Field | Value |
|---|---|
| ID | `VG-0277` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/management/controllers/cloning.py:192`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/management/controllers/cloning.py#L192). Engine message: `Unchecked_Input_for_Loop_Condition: form at indico/modules/events/management/controllers/cloning.py:188 reaches enumerate at indico/modules/events/management/controllers/cloning.py:192`.

```py
  190                          clone_event(self.event, n, start_dt, set(form.selected_items.data), form.category.data,
  191                                      form.refresh_users.data)
  192                          for n, start_dt in enumerate(dates, 1)
  193                      ]
  194                      if clones:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/management/controllers/cloning.py:192` and, if so, apply the standard mitigation for CWE-606.
