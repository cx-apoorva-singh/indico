# Unchecked Input for Loop Condition in indico/modules/events/registration/controllers/management/reglists.py:608

| Field | Value |
|---|---|
| ID | `VG-0301` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/registration/controllers/management/reglists.py:608`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/controllers/management/reglists.py#L608). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/registration/controllers/management/reglists.py:582 reaches || at indico/modules/events/registration/controllers/management/reglists.py:608`.

```py
  606          settings = self._get_event_badge_settings(self.event)
  607          form = BadgeSettingsForm(self.event, template=self.template_id, tickets=self.TICKET_BADGES, **settings)
  608          all_registrations = [r for r in (self.registrations or self.regform.registrations) if r.is_active]
  609          registrations = self._filter_registrations(all_registrations)
  610          if self.event.is_locked:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/controllers/management/reglists.py:608` and, if so, apply the standard mitigation for CWE-606.
