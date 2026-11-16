# Stored Command Injection in indico/legacy/pdfinterface/latex.py:195

| Field | Value |
|---|---|
| ID | `VG-0131` |
| Severity | **High** |
| Status | open |
| CWE | CWE-77 |
| Rule | `Python_Stored_Command_Injection` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Stored_Command_Injection` (CWE-77) reports an issue at [`indico/legacy/pdfinterface/latex.py:195`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/legacy/pdfinterface/latex.py#L195). Engine message: `Stored_Command_Injection: log_file at indico/legacy/pdfinterface/latex.py:255 reaches check_call at indico/legacy/pdfinterface/latex.py:195`.

```py
  193          try:
  194              # set config which limits location of input/output files
  195              subprocess.check_call(
  196                  pdflatex_cmd,
  197                  stdout=log_file,
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/legacy/pdfinterface/latex.py:195` and, if so, apply the standard mitigation for CWE-77.
