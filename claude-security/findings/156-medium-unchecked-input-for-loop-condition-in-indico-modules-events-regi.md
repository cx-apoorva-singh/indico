# Unchecked Input for Loop Condition in indico/modules/events/registration/controllers/management/sections.py:159

| Field | Value |
|---|---|
| ID | `VG-0303` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/registration/controllers/management/sections.py:159`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/controllers/management/sections.py#L159). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/registration/controllers/management/sections.py:157 reaches enumerate at indico/modules/events/registration/controllers/management/sections.py:159`.

```py
  157                                  .all()))
  158          self.section.position = new_position
  159          for pos, section in enumerate(to_update, start_enum):
  160              section.position = pos
  161          db.session.flush()
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/controllers/management/sections.py:159` and, if so, apply the standard mitigation for CWE-606.
