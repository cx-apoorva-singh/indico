# Object Access Violation in indico/modules/events/papers/operations.py:65

| Field | Value |
|---|---|
| ID | `VG-0094` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-99 |
| Rule | `Python_Object_Access_Violation` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Object_Access_Violation` (CWE-99) reports an issue at [`indico/modules/events/papers/operations.py:65`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/papers/operations.py#L65). Engine message: `Object_Access_Violation: all at indico/modules/events/papers/operations.py:62 reaches getattr at indico/modules/events/papers/operations.py:65`.

```py
   63          changed_contribs.update(contribs)
   64          for contrib in contribs:
   65              getattr(contrib, attr.key).difference_update(removed)
   66      return changed_contribs
   67  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/papers/operations.py:65` and, if so, apply the standard mitigation for CWE-99.
