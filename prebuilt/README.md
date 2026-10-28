# Prebuilt executables

Standalone `unlicense.exe` builds of commit `bb5e250`, which handles
Themida/WinLicense 3.x `ExitProcess` wrappers that call `SetCurrentDirectoryW`
to fool emulation.

Note: earlier builds from this folder are affected by bugs, don't use dumps
made with them:
- `0d36a4d` could go past the end of the IAT and overwrite the data following
  it.
- `0d36a4d` and `c201914` could resolve an `ExitProcess` import as
  `SetCurrentDirectoryW`.

| File | Architecture | Use for | SHA-256 |
|---|---|---|---|
| `x86/unlicense.exe` | 32-bit (PE32) | 32-bit targets | `e8fd78373ade3271826d47f868735b04eb8a94d1d7a87e2583526f590f5291ac` |
| `x64/unlicense.exe` | 64-bit (PE32+) | 64-bit targets | `069faf14db681109e2de0541c33e4c5793887f80d1e190355e007077a1b77d89` |

Use the build matching the target's architecture: 32-bit targets must be
dumped with the 32-bit (`x86`) build.

```
unlicense.exe --verbose target.exe
```

## How these were built

- `pyinstaller unlicense.spec` (PyInstaller 5.13.0), run with the official
  Windows CPython 3.11.9 (x86 and x64) under Wine 9.0, not on the GitHub
  Actions Windows runners.
- Dependencies match `poetry.lock` (capstone 4.0.2, fire 0.4.0, frida 16.1.3,
  lief 0.13.2, pyscylla 0.11.1, unicorn 1.0.3), except **xxhash 3.4.1**
  instead of 2.0.2, which has no prebuilt wheel for Python 3.11 on Windows.
  Only `xxhash.xxh32` is used, whose output is the same in both versions.
- The executables are not code-signed, so Windows SmartScreen or antivirus
  software may flag them.
