# Unchecked Input for Loop Condition in indico/modules/events/controllers/base.py:90

| Field | Value |
|---|---|
| ID | `VG-0263` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/controllers/base.py:90`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/controllers/base.py#L90). Engine message: `Unchecked_Input_for_Loop_Condition: order_by at indico/modules/events/registration/util.py:834 reaches displayed_regforms at indico/modules/events/controllers/base.py:90`.

```py
   88      def _show_registration_form(self):
   89          displayed_regforms = get_event_regforms_registrations(self.event, session.user)[0]
   90          if displayed_regforms and all(r.require_login for r in displayed_regforms) and not session.user:
   91              # force the user to log in first. like this they will go back to the page they tried to
   92              # originally access in case they are already registered for the event
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/controllers/base.py:90` and, if so, apply the standard mitigation for CWE-606.
