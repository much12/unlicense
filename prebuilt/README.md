# Prebuilt executables

Standalone `unlicense.exe` builds of commit `0d36a4d` (`main`), which includes
the fix for call-style wrapped imports in Themida/WinLicense 3.x.

| File | Architecture | Use for | SHA-256 |
|---|---|---|---|
| `x86/unlicense.exe` | 32-bit (PE32) | 32-bit targets | `474855fd96eb75d6488112c737f2def86af69b31a714c0adcfc41d3908ff6209` |
| `x64/unlicense.exe` | 64-bit (PE32+) | 64-bit targets | `958941ad29393b1f23448bb05aea194be6175796669585e1b1a48813507e93f1` |

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
