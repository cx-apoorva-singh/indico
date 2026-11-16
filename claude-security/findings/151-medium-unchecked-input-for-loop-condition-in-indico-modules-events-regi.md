# Unchecked Input for Loop Condition in indico/modules/events/registration/controllers/display.py:274

| Field | Value |
|---|---|
| ID | `VG-0298` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/registration/controllers/display.py:274`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/controllers/display.py#L274). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/registration/controllers/display.py:269 reaches regforms at indico/modules/events/registration/controllers/display.py:274`.

```py
  272          else:
  273              tables = []
  274              regforms_dict = {regform.id: regform for regform in regforms}
  275              for form_id in registration_settings.get_participant_list_form_ids(self.event):
  276                  try:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/controllers/display.py:274` and, if so, apply the standard mitigation for CWE-606.
