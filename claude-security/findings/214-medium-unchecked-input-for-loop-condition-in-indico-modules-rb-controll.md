# Unchecked Input for Loop Condition in indico/modules/rb/controllers/backend/admin.py:93

| Field | Value |
|---|---|
| ID | `VG-0361` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/controllers/backend/admin.py:93`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/controllers/backend/admin.py#L93). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/rb/controllers/backend/admin.py:92 reaches query at indico/modules/rb/controllers/backend/admin.py:93`.

```py
   91      def _jsonify_many(self):
   92          query = Location.query.filter(~Location.is_deleted).options(joinedload('acl_entries'))
   93          locations = [loc for loc in query if loc.can_manage(session.user)]
   94          return admin_locations_schema.jsonify(locations)
   95  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/controllers/backend/admin.py:93` and, if so, apply the standard mitigation for CWE-606.
