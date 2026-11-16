# Trust Boundary Violation in Session Variables in indico/modules/auth/controllers.py:712

| Field | Value |
|---|---|
| ID | `VG-0137` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/auth/controllers.py:712`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/auth/controllers.py#L712). Engine message: `Trust_Boundary_Violation_in_Session_Variables: get at indico/modules/auth/controllers.py:710 reaches session at indico/modules/auth/controllers.py:712`.

```py
  710          next_url = request.args.get('next')
  711          if next_url and multipass.validate_next_url(next_url):
  712              session['register_next_url'] = next_url
  713  
  714      def get_signup_config(self):
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/auth/controllers.py:712` and, if so, apply the standard mitigation for CWE-501.
