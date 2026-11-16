# Object Access Violation in indico/util/signals.py:71

| Field | Value |
|---|---|
| ID | `VG-0110` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-99 |
| Rule | `Python_Object_Access_Violation` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Object_Access_Violation` (CWE-99) reports an issue at [`indico/util/signals.py:71`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/util/signals.py#L71). Engine message: `Object_Access_Violation: options at indico/modules/events/abstracts/controllers/management.py:177 reaches getattr at indico/util/signals.py:71`.

```py
   69          for plugin, cls in objects:
   70              setattr(cls, plugin_attr, plugin)
   71      mapping = {getattr(cls, name_attr): cls for _, cls in objects}
   72      # check for two different objects having the same name, e.g. because of
   73      # two plugins using a too generic name for their object
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/util/signals.py:71` and, if so, apply the standard mitigation for CWE-99.
