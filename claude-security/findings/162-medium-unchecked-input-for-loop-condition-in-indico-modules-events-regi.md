# Unchecked Input for Loop Condition in indico/modules/events/registration/stats.py:147

| Field | Value |
|---|---|
| ID | `VG-0309` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/registration/stats.py:147`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/stats.py#L147). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/registration/stats.py:136 reaches all_items at indico/modules/events/registration/stats.py:147`.

```py
  145          data = defaultdict(list)
  146          all_items = sorted(self._regitems, key=self._build_key)
  147          items_with_price = [regitem for regitem in all_items if regitem.price]
  148          items_without_price = [regitem for regitem in all_items if not regitem.price]
  149          for k, items in groupby(items_with_price, key=self._build_key):
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/stats.py:147` and, if so, apply the standard mitigation for CWE-606.
