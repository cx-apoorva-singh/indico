# Unchecked Input for Loop Condition in indico/modules/events/api.py:753

| Field | Value |
|---|---|
| ID | `VG-0250` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/api.py:753`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/api.py#L753). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/api.py:746 reaches sessions at indico/modules/events/api.py:753`.

```py
  751          """Return an aggregated list of session blocks given the sessions."""
  752          session_blocks = []
  753          for session_ in sessions:
  754              can_manage = self.user is not None and session_.can_manage(self.user)
  755              session_access_list = None
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/api.py:753` and, if so, apply the standard mitigation for CWE-606.
