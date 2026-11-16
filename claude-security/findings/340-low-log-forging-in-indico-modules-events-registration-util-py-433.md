# Log Forging in indico/modules/events/registration/util.py:433

| Field | Value |
|---|---|
| ID | `VG-0074` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-117 |
| Rule | `Python_Log_Forging` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Log_Forging` (CWE-117) reports an issue at [`indico/modules/events/registration/util.py:433`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/util.py#L433). Engine message: `Log_Forging: json at indico/modules/events/registration/controllers/management/reglists.py:383 reaches info at indico/modules/events/registration/util.py:433`.

```py
  431      signals.event.registration_created.send(registration, management=management, data=data)
  432      notify_registration_creation(registration, notify_user=notify_user, from_management=management)
  433      logger.info('New registration %s by %s', registration, user)
  434      registration.log(EventLogRealm.management if management else EventLogRealm.participants,
  435                       LogKind.positive, 'Registration',
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/util.py:433` and, if so, apply the standard mitigation for CWE-117.
