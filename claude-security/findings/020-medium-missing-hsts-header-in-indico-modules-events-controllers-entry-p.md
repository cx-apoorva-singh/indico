# Missing HSTS Header in indico/modules/events/controllers/entry.py:34

| Field | Value |
|---|---|
| ID | `VG-0085` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-346 |
| Rule | `Python_Missing_HSTS_Header` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Missing_HSTS_Header` (CWE-346) reports an issue at [`indico/modules/events/controllers/entry.py:34`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/controllers/entry.py#L34). Engine message: `Missing_HSTS_Header:`.

```py
   32          else:
   33              request.view_args['event_id'] = int(event_id)
   34              return RHDisplayEvent().process()
   35      else:
   36          shorturl_event = (Event.query
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/controllers/entry.py:34` and, if so, apply the standard mitigation for CWE-346.
