# Unchecked Input for Loop Condition in indico/modules/vc/controllers.py:353

| Field | Value |
|---|---|
| ID | `VG-0427` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/vc/controllers.py:353`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/vc/controllers.py#L353). Engine message: `Unchecked_Input_for_Loop_Condition: limit at indico/modules/vc/controllers.py:351 reaches query at indico/modules/vc/controllers.py:353`.

```py
  351                   .limit(10))
  352  
  353          return ((room, count) for room, count in query if room.plugin.can_manage_vc_room(session.user, room))
  354  
  355      def _process(self):
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/vc/controllers.py:353` and, if so, apply the standard mitigation for CWE-606.
