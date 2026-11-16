# Unchecked Input for Loop Condition in indico/modules/events/timetable/controllers/legacy.py:80

| Field | Value |
|---|---|
| ID | `VG-0339` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/timetable/controllers/legacy.py:80`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/timetable/controllers/legacy.py#L80). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/timetable/controllers/legacy.py:79 reaches breaks at indico/modules/events/timetable/controllers/legacy.py:80`.

```py
   78      def _get_default_colors(self):
   79          breaks = Break.query.filter(Break.timetable_entry.has(event=self.event)).all()
   80          common_colors = Counter(b.colors for b in breaks)
   81          most_common = common_colors.most_common(1)
   82          return most_common[0][0] if most_common else get_random_color(self.event)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/timetable/controllers/legacy.py:80` and, if so, apply the standard mitigation for CWE-606.
