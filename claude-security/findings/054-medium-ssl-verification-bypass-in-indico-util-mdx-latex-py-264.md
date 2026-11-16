# SSL Verification Bypass in indico/util/mdx_latex.py:264

| Field | Value |
|---|---|
| ID | `VG-0121` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-599 |
| Rule | `Python_SSL_Verification_Bypass` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_SSL_Verification_Bypass` (CWE-599) reports an issue at [`indico/util/mdx_latex.py:264`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/util/mdx_latex.py#L264). Engine message: `SSL_Verification_Bypass: false at indico/util/mdx_latex.py:264 reaches get at indico/util/mdx_latex.py:264`.

```py
  262          else:
  263              try:
  264                  resp = requests.get(src, verify=False, timeout=5)  # noqa: S501
  265              except InvalidURL:
  266                  raise ImageURLException(f"Cannot understand URL '{src}'")
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/util/mdx_latex.py:264` and, if so, apply the standard mitigation for CWE-599.
