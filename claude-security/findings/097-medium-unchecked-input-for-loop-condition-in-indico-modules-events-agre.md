# Unchecked Input for Loop Condition in indico/modules/events/agreements/controllers.py:178

| Field | Value |
|---|---|
| ID | `VG-0244` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/agreements/controllers.py:178`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/agreements/controllers.py#L178). Engine message: `Unchecked_Input_for_Loop_Condition: form at indico/modules/events/agreements/controllers.py:168 reaches agreements at indico/modules/events/agreements/controllers.py:178`.

```py
  176          agreements = self._get_agreements()
  177          sender_address = self.event.get_verbose_email_sender(form.sender_address.data)
  178          for agreement in agreements:
  179              notify_agreement_reminder(agreement, email_body, form.cc_addresses.data, sender_address)
  180          flash(_('Reminders sent'), 'success')
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/agreements/controllers.py:178` and, if so, apply the standard mitigation for CWE-606.
