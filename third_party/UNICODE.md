# Unicode data in the NuGet ID profile

`internal/nuget/id_unicode_profile.go` contains generated Unicode character data:

- Word categories from [UnicodeData 16.0.0](https://www.unicode.org/Public/16.0.0/ucd/UnicodeData.txt), SHA-256 `ff58e5823bd095166564a006e47d111130813dcf8bf234ef79fa51a870edb48f`.
- Simple lowercase mappings from [UnicodeData 15.1.0](https://www.unicode.org/Public/15.1.0/ucd/UnicodeData.txt), SHA-256 `2fc713e6a31a87c4850a37fe2caffa4218180fadb5de86b43a143ddb4581fb86`.

Copyright 1991–2026 Unicode, Inc. These data are provided under
[Unicode License V3](licenses/Unicode-3.0.txt). The generator and lookup code are
original cratectl code. The source file carries both license identifiers.

The frozen combination reproduces the observed SDK ID contract; it does not
assert which Unicode database an SDK internally uses. The explicit invariant
dotted-I rule remains part of the original lookup implementation.

Regenerate offline with the exact hash-checked inputs:

```sh
python3 scripts/generate_nuget_id_profile.py \
  --word-data .cache/nuget-id-unicode/UnicodeData-16.0.0.txt \
  --case-data .cache/nuget-id-unicode/UnicodeData-15.1.0.txt \
  --output internal/nuget/id_unicode_profile.go --check
```

Omit `--check` to regenerate. The script bounds input and fails on a changed
source hash. Profile changes require explicit compatibility evidence for
existing coordinates and native clients; a Go runtime upgrade must not silently
change package keys.
