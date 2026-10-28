# Prebuilt executables

Standalone `unlicense.exe` builds of commit `c201914`, which includes the fix
for call-style wrapped imports in Themida/WinLicense 3.x.

Note: builds of `0d36a4d` (the previous version of this folder) could go past
the end of the IAT and overwrite the data following it. Don't use dumps made
with them.

| File | Architecture | Use for | SHA-256 |
|---|---|---|---|
| `x86/unlicense.exe` | 32-bit (PE32) | 32-bit targets | `14aa6c74c7f4fe22c7ba527ac49c57e732a29772f571dfc8d6edab216ce79766` |
| `x64/unlicense.exe` | 64-bit (PE32+) | 64-bit targets | `0ed5ddca31454af3b0972e603060cab9ee94abff1c67943bfb3dd7376b0527f3` |

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
