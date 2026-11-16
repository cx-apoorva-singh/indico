# Unchecked Input for Loop Condition in indico/modules/receipts/controllers/event.py:302

| Field | Value |
|---|---|
| ID | `VG-0407` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/receipts/controllers/event.py:302`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/receipts/controllers/event.py#L302). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/receipts/controllers/event.py:296 reaches receipts at indico/modules/receipts/controllers/event.py:302`.

```py
  300              return self._generate_zip_file(self.receipts)
  301          output = PdfWriter()
  302          for receipt in self.receipts:
  303              with receipt.file.open() as fd:
  304                  output.append(fd)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/receipts/controllers/event.py:302` and, if so, apply the standard mitigation for CWE-606.
