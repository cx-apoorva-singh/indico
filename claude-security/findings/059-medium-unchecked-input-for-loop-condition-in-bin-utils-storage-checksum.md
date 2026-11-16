# Unchecked Input for Loop Condition in bin/utils/storage_checksums.py:51

| Field | Value |
|---|---|
| ID | `VG-0206` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`bin/utils/storage_checksums.py:51`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/bin/utils/storage_checksums.py#L51). Engine message: `Unchecked_Input_for_Loop_Condition: options at bin/utils/storage_checksums.py:32 reaches items at bin/utils/storage_checksums.py:51`.

```py
   49  def main():
   50      models = {model: make_query(model).count() for model in StoredFileMixin.__subclasses__()}
   51      models = {model: total for model, total in models.items() if total}
   52      labels = {model: cformat('Processing %{blue!}{}%{reset} (%{cyan}{}%{reset} rows)').format(model.__name__, total)
   53                for model, total in models.items()}
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `bin/utils/storage_checksums.py:51` and, if so, apply the standard mitigation for CWE-606.
