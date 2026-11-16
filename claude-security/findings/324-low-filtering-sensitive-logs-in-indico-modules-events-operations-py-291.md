# Filtering Sensitive Logs in indico/modules/events/operations.py:291

| Field | Value |
|---|---|
| ID | `VG-0057` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-532 |
| Rule | `Python_Filtering_Sensitive_Logs` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Filtering_Sensitive_Logs` (CWE-532) reports an issue at [`indico/modules/events/operations.py:291`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/operations.py#L291). Engine message: `Filtering_Sensitive_Logs: access_key at indico/modules/events/management/controllers/protection.py:87 reaches info at indico/modules/events/operations.py:291`.

```py
  289      db.session.flush()
  290      signals.event.updated.send(event, changes=changes)
  291      logger.info('Protection of event %r updated with %r by %r', event, data, session.user)
  292      if changes:
  293          log_fields = {'protection_mode': 'Protection mode',
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/operations.py:291` and, if so, apply the standard mitigation for CWE-532.
