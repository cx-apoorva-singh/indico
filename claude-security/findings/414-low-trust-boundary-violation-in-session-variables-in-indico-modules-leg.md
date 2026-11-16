# Trust Boundary Violation in Session Variables in indico/modules/legal/__init__.py:127

| Field | Value |
|---|---|
| ID | `VG-0197` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/legal/__init__.py:127`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/legal/__init__.py#L127). Engine message: `Trust_Boundary_Violation_in_Session_Variables: path at indico/modules/legal/__init__.py:127 reaches session at indico/modules/legal/__init__.py:127`.

```py
  125  
  126      # Everything else gets redirected to the terms page
  127      session['legal_agreement_return_path'] = request.path
  128      return redirect(url_for('legal.accept_agreement'))
  129  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/legal/__init__.py:127` and, if so, apply the standard mitigation for CWE-501.
