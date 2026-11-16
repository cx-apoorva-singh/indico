# Object Access Violation in indico/web/flask/templating.py:312

| Field | Value |
|---|---|
| ID | `VG-0112` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-99 |
| Rule | `Python_Object_Access_Violation` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Object_Access_Violation` (CWE-99) reports an issue at [`indico/web/flask/templating.py:312`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/web/flask/templating.py#L312). Engine message: `Object_Access_Violation: method at indico/web/rh.py:214 reaches getattr at indico/web/flask/templating.py:312`.

```py
  310  class IndicoEnvironment(PluginEnvironment):
  311      def getattr(self, obj, attribute):
  312          rv = super().getattr(obj, attribute)
  313          if isinstance(rv, StrictUndefined):
  314              # we only care about top-level undefineds, so if getting an attribute returns
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/web/flask/templating.py:312` and, if so, apply the standard mitigation for CWE-99.
