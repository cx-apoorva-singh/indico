# Trust Boundary Violation in Session Variables in indico/modules/events/util.py:272

| Field | Value |
|---|---|
| ID | `VG-0196` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/util.py:272`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/util.py#L272). Engine message: `Trust_Boundary_Violation_in_Session_Variables: args at indico/modules/events/util.py:269 reaches session at indico/modules/events/util.py:272`.

```py
  270              configuration = StaticListLink.load(self.event, self.list_link_type, uuid)
  271              if configuration and configuration['entry_parent_id'] == self.entry_parent.id:
  272                  session[session_key] = configuration['data']
  273          return session.get(session_key, self.default_list_config)
  274  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/util.py:272` and, if so, apply the standard mitigation for CWE-501.
