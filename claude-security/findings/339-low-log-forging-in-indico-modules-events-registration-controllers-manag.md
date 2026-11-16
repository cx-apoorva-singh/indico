# Log Forging in indico/modules/events/registration/controllers/management/sections.py:100

| Field | Value |
|---|---|
| ID | `VG-0073` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-117 |
| Rule | `Python_Log_Forging` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Log_Forging` (CWE-117) reports an issue at [`indico/modules/events/registration/controllers/management/sections.py:100`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/controllers/management/sections.py#L100). Engine message: `Log_Forging: json at indico/modules/events/registration/controllers/management/sections.py:73 reaches info at indico/modules/events/registration/controllers/management/sections.py:100`.

```py
   98              data={'Changes': changes}
   99          )
  100          logger.info('Section %s modified by %s: %s', self.section, session.user, changes)
  101          return jsonify(self.section.view_data)
  102  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/controllers/management/sections.py:100` and, if so, apply the standard mitigation for CWE-117.
