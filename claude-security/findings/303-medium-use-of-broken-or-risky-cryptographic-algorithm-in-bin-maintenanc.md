# Use of Broken or Risky Cryptographic Algorithm in bin/maintenance/dump_url_map.py:26

| Field | Value |
|---|---|
| ID | `VG-0450` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-327 |
| Rule | `Python_Use_of_Broken_or_Risky_Cryptographic_Algorithm` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Use_of_Broken_or_Risky_Cryptographic_Algorithm` (CWE-327) reports an issue at [`bin/maintenance/dump_url_map.py:26`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/bin/maintenance/dump_url_map.py#L26). Engine message: `Use_of_Broken_or_Risky_Cryptographic_Algorithm: hexdigest`.

```py
   24          h.update(subprocess.check_output(['git', 'status']))
   25          h.update(subprocess.check_output(['git', 'diff']))
   26      return h.hexdigest()
   27  
   28  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `bin/maintenance/dump_url_map.py:26` and, if so, apply the standard mitigation for CWE-327.
