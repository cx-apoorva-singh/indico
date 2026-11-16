# Object Access Violation in indico/core/storage/models.py:204

| Field | Value |
|---|---|
| ID | `VG-0088` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-99 |
| Rule | `Python_Object_Access_Violation` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Object_Access_Violation` (CWE-99) reports an issue at [`indico/core/storage/models.py:204`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/core/storage/models.py#L204). Engine message: `Object_Access_Violation: fd at indico/modules/events/layout/clone.py:41 reaches getattr at indico/core/storage/models.py:204`.

```py
  202          assert self.size is None
  203          if self.version_of:
  204              assert getattr(self, self.version_of) is not None
  205          self.storage_backend, path = self._build_storage_path()
  206          self.storage_file_id, self.md5 = self.storage.save(path, self.content_type, self.filename, data)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/core/storage/models.py:204` and, if so, apply the standard mitigation for CWE-99.
