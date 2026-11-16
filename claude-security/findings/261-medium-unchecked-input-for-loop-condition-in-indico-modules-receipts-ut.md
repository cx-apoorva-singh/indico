# Unchecked Input for Loop Condition in indico/modules/receipts/util.py:137

| Field | Value |
|---|---|
| ID | `VG-0408` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/receipts/util.py:137`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/receipts/util.py#L137). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/receipts/util.py:136 reaches query at indico/modules/receipts/util.py:137`.

```py
  135                       ~ReceiptTemplate.category.has(Category.is_deleted))
  136               .options(joinedload('event')))
  137      templates = ({t for t in query if t.owner.can_manage(user)} - get_all_templates(obj) - set(obj.receipt_templates))
  138      now = now_utc()
  139      templates = sorted(templates, key=lambda x: x.event.start_dt if x.event else now, reverse=True)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/receipts/util.py:137` and, if so, apply the standard mitigation for CWE-606.
