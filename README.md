# DelphiGhidra

Small Jython script for Ghidra that heuristically finds Delphi class-name strings and tries to locate probable VMTs (virtual method tables). A starter tool — verify results manually.

---

## Quick start

1. Put `DelphiGhidra.py` into Ghidra’s scripts folder (or import via Script Manager).  
2. Open your Delphi binary in Ghidra and let the auto-analysis finish.  
3. Run the script from Script Manager.  
4. Watch the Ghidra Console for live progress (it prints each processed string).  
5. Script actions:
   - creates a `STR_<Name>` label at each detected class-like string
   - attempts to find and label `VMT_<Name>_<offset>` candidates and creates pointer data (if safe)

---

## Why use it

- Helps find Delphi class names and candidate VMTs fast.
- Leaves persistent labels while running so you can stop anytime and keep work so far.
- Heuristic — not perfect, but useful to speed manual reversing.

---

## Config (top of script)

- `BACKSCAN_BYTES` — how far back from a reference to search for pointers (default `0x400`)  
- `MAX_REFERENCES_TO_CONSIDER` — refs per string (default `64`)  
- `MAX_POINTER_FIELDS` — pointers to create at a candidate VMT (default `6`)  
- `POINTER_SIZE` — 4 for 32-bit, 8 for 64-bit  
- `ALWAYS_LABEL_STRINGS` — label the string address (useful to track progress)  
- `DEBUG` — verbose output

Change values in the script to tune speed/accuracy.

---

## Tips

- If you get few hits: increase `BACKSCAN_BYTES`.  
- If you get many false positives: decrease `BACKSCAN_BYTES`, increase `MIN_STRING_LEN`, or require N table entries point into executable blocks.  
- For 64-bit: set `POINTER_SIZE = 8` and replace `mem.getInt()` reads with `mem.getLong()` where needed.

---

## Output example

Console:
```
Processing string 1: TObject
  refs(raw) = 3
  refs(total) = 3
Marked candidate VMT at 0x0040a0d8 for class TObject
```

In Ghidra:
- `STR_TObject` label at string
- `VMT_TObject_40a0d8` label and pointer data at candidate table

---

## Limitations

- Heuristic: can miss or mislabel VMTs (especially in packed/obfuscated binaries).  
- Requires manual verification. Use as a helper, not an authoritative tool.

---

## License

Use/modify freely. No warranty — use at your own risk.
