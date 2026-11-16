# Log Forging in indico/modules/events/layout/controllers/layout.py:194

| Field | Value |
|---|---|
| ID | `VG-0071` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-117 |
| Rule | `Python_Log_Forging` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Log_Forging` (CWE-117) reports an issue at [`indico/modules/events/layout/controllers/layout.py:194`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/layout/controllers/layout.py#L194). Engine message: `Log_Forging: files at indico/modules/events/layout/controllers/layout.py:168 reaches info at indico/modules/events/layout/controllers/layout.py:194`.

```py
  192          flash(_('New logo saved'), 'success')
  193          self._check_and_flash_logo_warnings(img)
  194          logger.info("New logo '%s' uploaded by %s (%s)", f.filename, session.user, self.event)
  195          return jsonify_data(content=get_logo_data(self.event))
  196  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/layout/controllers/layout.py:194` and, if so, apply the standard mitigation for CWE-117.
