# Unchecked Input for Loop Condition in indico/modules/rb/util.py:98

| Field | Value |
|---|---|
| ID | `VG-0404` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/util.py:98`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/util.py#L98). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/rb/util.py:87 reaches enumerate at indico/modules/rb/util.py:98`.

```py
   96      sprite.paste(image, (0, 0))
   97      mapping = {}
   98      for count, room in enumerate(rooms, start=1):
   99          location = image_width * count
  100          image = Image.open(BytesIO(room.photo.data)).resize(ROOM_PHOTO_DIMENSIONS, Image.LANCZOS)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/util.py:98` and, if so, apply the standard mitigation for CWE-606.
