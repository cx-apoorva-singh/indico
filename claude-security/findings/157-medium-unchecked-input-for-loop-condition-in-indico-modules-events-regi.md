# Unchecked Input for Loop Condition in indico/modules/events/registration/fields/sessions.py:60

| Field | Value |
|---|---|
| ID | `VG-0304` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/registration/fields/sessions.py:60`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/fields/sessions.py#L60). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/registration/fields/sessions.py:59 reaches session_blocks at indico/modules/events/registration/fields/sessions.py:60`.

```py
   58                            .options(joinedload(SessionBlock.timetable_entry).raiseload('*'))
   59                            .all())
   60          return {str(b.id): _format_block(b, event.tzinfo) for b in session_blocks}
   61  
   62      def get_validators(self, existing_registration):
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/fields/sessions.py:60` and, if so, apply the standard mitigation for CWE-606.
