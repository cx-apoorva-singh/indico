# Log Forging in indico/modules/categories/controllers/management.py:197

| Field | Value |
|---|---|
| ID | `VG-0066` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-117 |
| Rule | `Python_Log_Forging` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Log_Forging` (CWE-117) reports an issue at [`indico/modules/categories/controllers/management.py:197`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/categories/controllers/management.py#L197). Engine message: `Log_Forging: files at indico/modules/categories/controllers/management.py:171 reaches info at indico/modules/categories/controllers/management.py:197`.

```py
  195          self._set_image(content, metadata)
  196          flash(self.SAVED_FLASH_MSG, 'success')
  197          logger.info(f"New {self.IMAGE_TYPE} '%s' uploaded by %s (%s)", f.filename, session.user, self.category)
  198          return jsonify_data(content=get_image_data(self.IMAGE_TYPE, self.category))
  199  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/categories/controllers/management.py:197` and, if so, apply the standard mitigation for CWE-117.
