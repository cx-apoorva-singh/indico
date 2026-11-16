# Log Forging in indico/modules/events/registration/controllers/management/sections.py:53

| Field | Value |
|---|---|
| ID | `VG-0072` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-117 |
| Rule | `Python_Log_Forging` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Log_Forging` (CWE-117) reports an issue at [`indico/modules/events/registration/controllers/management/sections.py:53`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/controllers/management/sections.py#L53). Engine message: `Log_Forging: json at indico/modules/events/registration/controllers/management/sections.py:43 reaches info at indico/modules/events/registration/controllers/management/sections.py:53`.

```py
   51              data={'Manager-only': section.is_manager_only}
   52          )
   53          logger.info('Section %s created by %s', section, session.user)
   54          return jsonify(section.view_data)
   55  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/controllers/management/sections.py:53` and, if so, apply the standard mitigation for CWE-117.
