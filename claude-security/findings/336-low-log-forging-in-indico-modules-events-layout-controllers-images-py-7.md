# Log Forging in indico/modules/events/layout/controllers/images.py:70

| Field | Value |
|---|---|
| ID | `VG-0070` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-117 |
| Rule | `Python_Log_Forging` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Log_Forging` (CWE-117) reports an issue at [`indico/modules/events/layout/controllers/images.py:70`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/layout/controllers/images.py#L70). Engine message: `Log_Forging: files at indico/modules/events/layout/controllers/images.py:45 reaches info at indico/modules/events/layout/controllers/images.py:70`.

```py
   68              num += 1
   69              db.session.flush()
   70              logger.info('Image %s uploaded by %s', image, session.user)
   71              signals.event_management.image_created.send(image, user=session.user)
   72          flash(ngettext('The image has been uploaded', '{count} images have been uploaded', num)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/layout/controllers/images.py:70` and, if so, apply the standard mitigation for CWE-117.
