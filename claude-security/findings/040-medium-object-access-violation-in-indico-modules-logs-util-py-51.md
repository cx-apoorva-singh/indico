# Object Access Violation in indico/modules/logs/util.py:51

| Field | Value |
|---|---|
| ID | `VG-0105` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-99 |
| Rule | `Python_Object_Access_Violation` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Object_Access_Violation` (CWE-99) reports an issue at [`indico/modules/logs/util.py:51`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/logs/util.py#L51). Engine message: `Object_Access_Violation: json at indico/modules/events/registration/controllers/management/sections.py:73 reaches getattr at indico/modules/logs/util.py:51`.

```py
   49          not_none_change = [x for x in change if x is not None]
   50          if attr:
   51              change = [getattr(x, attr) if x is not None else '' for x in change]
   52          if convert:
   53              change = convert(change)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/logs/util.py:51` and, if so, apply the standard mitigation for CWE-99.
