# ER_shared

Go code for Elden Ring saves, shared by DrippingSoup22's editors: a decrypted
PS4 `memory.dat` or an unencrypted PC `ER0000.sl2` (a Steam-encrypted one is
refused). It holds format code only; what the game's data means is not here.

| Package | What it is |
|---|---|
| `regulation/` | The save container on both platforms (with PC's per-region MD5) and the regulation inside it: AES and DCX/ZSTD, BND4 archive entries, PARAM tables, inserting and removing rows (each operation proves every other row survived), the registry of measured table layouts, and Paramdex schemas for decoding rows by field name. |
| `charslot/` | The ten character slots: which hold a character, its name and level, and its event flags, read and written through the game's block table. |
| `releasezip/` | Packs one release folder into a ZIP: keeps executable bits, writes through a temporary file, never overwrites. `go run github.com/DrippingSoup22/ER_shared/releasezip -root <folder> -out <file.zip>`. |

## Use

```sh
go get github.com/DrippingSoup22/ER_shared@latest
```

```go
import reg "github.com/DrippingSoup22/ER_shared/regulation"
```

These rules hold for every writer built on it:

- Never overwrite an input save. `WriteAtomicValidated` writes beside the
  output, validates the result, then renames it, and refuses an existing file;
  `ReplaceAtomicValidated` may replace an output the user chose, never the
  input.
- Detect the platform from the file (`DetectPlatform`), never from its name,
  and refresh a PC region's digest after editing it (`Build` does the
  regulation's, `charslot.RefreshDigest` a slot's).
- A table is opened through its `TableLayout` (`MustLayout("BuddyParam")`), so
  a regulation whose stride or schema has changed is refused instead of being
  written at guessed offsets.

## Tests

```sh
go test ./...
```

The tests that need a real save read `ER_SAVE` and skip without it; the
Paramdex checks read `ER_PARAMDEX_ROOT`
([soulsmods/Paramdex](https://github.com/soulsmods/Paramdex)).

## License

Copyright (C) 2026 DrippingSoup22. Free software under the GNU General Public
License, version 3 or (at your option) any later version; see
[LICENSE](LICENSE). The container code descends from ER Merchant Editor's save
code, which came from SaveForge-derived work. `charslot`'s identity offsets and
event-flag block table come from
[EldenRing-SaveForge](https://github.com/oisis/EldenRing-SaveForge) (GPL-3.0).
