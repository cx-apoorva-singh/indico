# Unchecked Input for Loop Condition in indico/modules/categories/controllers/display.py:640

| Field | Value |
|---|---|
| ID | `VG-0220` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/categories/controllers/display.py:640`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/categories/controllers/display.py#L640). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/categories/controllers/display.py:596 reaches event_query at indico/modules/categories/controllers/display.py:640`.

```py
  638          allowed_keywords_set = set(allowed_keywords)
  639          tz = self.category.display_tzinfo
  640          for event in event_query:
  641              valid_keywords = [keyword for keyword in event.keywords if keyword in allowed_keywords_set]
  642              for keyword in valid_keywords:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/categories/controllers/display.py:640` and, if so, apply the standard mitigation for CWE-606.
