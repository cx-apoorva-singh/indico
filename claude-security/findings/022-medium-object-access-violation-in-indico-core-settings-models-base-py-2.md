# Object Access Violation in indico/core/settings/models/base.py:200

| Field | Value |
|---|---|
| ID | `VG-0087` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-99 |
| Rule | `Python_Object_Access_Violation` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Object_Access_Violation` (CWE-99) reports an issue at [`indico/core/settings/models/base.py:200`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/core/settings/models/base.py#L200). Engine message: `Object_Access_Violation: filter_by at indico/core/settings/models/base.py:201 reaches getattr at indico/core/settings/models/base.py:200`.

```py
  198      @classmethod
  199      def merge_users(cls, module, target, source):
  200          settings = [(setting.module, setting.name, {x: getattr(setting, x) for x in cls.extra_key_cols})
  201                      for setting in cls.query.filter_by(module=module, type=PrincipalType.user, user=source)]
  202          for mod, name, extra in settings:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/core/settings/models/base.py:200` and, if so, apply the standard mitigation for CWE-99.
