# Unchecked Input for Loop Condition in indico/core/settings/util.py:40

| Field | Value |
|---|---|
| ID | `VG-0213` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/core/settings/util.py:40`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/core/settings/util.py#L40). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/core/settings/util.py:37 reaches settings at indico/core/settings/util.py:40`.

```py
   38      cache = proxy._cache
   39      get_kwargs_val = attrgetter(filter_col.key)
   40      for setting in settings:
   41          kwargs = {filter_col.key: get_kwargs_val(setting)}
   42          cache_key = _get_cache_key(proxy, setting.name, kwargs)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/core/settings/util.py:40` and, if so, apply the standard mitigation for CWE-606.
