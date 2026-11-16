# Object Access Violation in indico/util/signals.py:76

| Field | Value |
|---|---|
| ID | `VG-0111` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-99 |
| Rule | `Python_Object_Access_Violation` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Object_Access_Violation` (CWE-99) reports an issue at [`indico/util/signals.py:76`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/util/signals.py#L76). Engine message: `Object_Access_Violation: options at indico/modules/events/abstracts/controllers/management.py:177 reaches getattr at indico/util/signals.py:76`.

```py
   74      conflicting = {cls for _, cls in objects} - set(mapping.values())
   75      if conflicting:
   76          names = ', '.join(sorted(getattr(x, name_attr) for x in conflicting))
   77          raise RuntimeError(f'Non-unique object names: {names}')
   78      return mapping
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/util/signals.py:76` and, if so, apply the standard mitigation for CWE-99.
