# Unchecked Input for Loop Condition in indico/modules/events/abstracts/controllers/display.py:49

| Field | Value |
|---|---|
| ID | `VG-0233` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/abstracts/controllers/display.py:49`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/abstracts/controllers/display.py#L49). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/abstracts/util.py:251 reaches abstracts at indico/modules/events/abstracts/controllers/display.py:49`.

```py
   47          data = generate_cached_pdf(
   48              lambda: AbstractsToPDF(self.event, abstracts).generate(as_bytes=True),
   49              ('my-abstracts', '-'.join(sorted(str(a.id) for a in abstracts))),
   50          )
   51          return send_file('my-abstracts.pdf', data, 'application/pdf')
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/abstracts/controllers/display.py:49` and, if so, apply the standard mitigation for CWE-606.
