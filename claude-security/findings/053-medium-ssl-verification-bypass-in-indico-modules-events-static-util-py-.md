# SSL Verification Bypass in indico/modules/events/static/util.py:48

| Field | Value |
|---|---|
| ID | `VG-0120` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-599 |
| Rule | `Python_SSL_Verification_Bypass` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_SSL_Verification_Bypass` (CWE-599) reports an issue at [`indico/modules/events/static/util.py:48`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/static/util.py#L48). Engine message: `SSL_Verification_Bypass: false at indico/modules/events/static/util.py:48 reaches get at indico/modules/events/static/util.py:48`.

```py
   46  def _create_data_uri(url, filename):
   47      """Create a data url that contains the file in question."""
   48      response = requests.get(url, verify=False)  # noqa: S501
   49      if response.status_code != 200:
   50          # couldn't access the file
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/static/util.py:48` and, if so, apply the standard mitigation for CWE-599.
