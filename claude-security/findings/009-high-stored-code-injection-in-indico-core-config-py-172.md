# Stored Code Injection in indico/core/config.py:172

| Field | Value |
|---|---|
| ID | `VG-0124` |
| Severity | **High** |
| Status | open |
| CWE | CWE-94 |
| Rule | `Python_Stored_Code_Injection` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Stored_Code_Injection` (CWE-94) reports an issue at [`indico/core/config.py:172`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/core/config.py#L172). Engine message: `Stored_Code_Injection: read at indico/core/config.py:172 reaches exec at indico/core/config.py:172`.

```py
  170      locals_ = {}
  171      with codecs.open(path, encoding='utf-8') as config_file:
  172          exec(compile(config_file.read(), path, 'exec'), globals_, locals_)  # noqa: S102
  173      return {str(k if k.isupper() else _convert_key(k)): v
  174              for k, v in locals_.items()
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/core/config.py:172` and, if so, apply the standard mitigation for CWE-94.
