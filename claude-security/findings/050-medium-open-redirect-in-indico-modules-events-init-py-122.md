# Open Redirect in indico/modules/events/__init__.py:122

| Field | Value |
|---|---|
| ID | `VG-0115` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-601 |
| Rule | `Python_Open_Redirect` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Open_Redirect` (CWE-601) reports an issue at [`indico/modules/events/__init__.py:122`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/__init__.py#L122). Engine message: `Open_Redirect: url at indico/modules/events/__init__.py:121 reaches redirect at indico/modules/events/__init__.py:122`.

```py
  120  
  121          new_url = _legacy_event_id_re.sub(f'/event/{mapping.event_id}', request.url, count=1)
  122          return redirect(new_url, 302 if app.debug else 301)
  123  
  124  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=Y). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/__init__.py:122` and, if so, apply the standard mitigation for CWE-601.
