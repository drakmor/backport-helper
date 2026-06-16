# libSceRtc Backport Stub

`libSceRtc` replacement module.

This is a special compatibility version of the library. It is intended to add
missing functions and hook existing functions so applications can run on older
SDK and firmware versions.

The module exports the public RTC API plus the extra entry points present in the
reference `libSceRtc.sprx`: current clock/network clock helpers, date conversion,
tick arithmetic, RFC2822/RFC3339 parsing and formatting, DOS/Win32/time_t
conversion, and tick comparison.

Build with Visual Studio Prospero platform:

```text
msbuild libSceRtc.sln /p:Configuration=Release /p:Platform=Prospero
```

Visual Studio also exposes `Backport4|Prospero` through `Backport13|Prospero`
solution configurations for building a single target variant directly from the
IDE.

The default Release build also generates compatibility variants:

```text
out/sdk4/libSceRtc.prx
out/sdk5/libSceRtc.prx
...
out/sdk13/libSceRtc.prx
```

Add version-specific exports to `backports.cpp` and guard them by target version:

```c
#if BACKPORT_SDK <= 6
PRX_INTERFACE int sceRtcNewCompatExport(void) {
    return SCE_OK;
}
#endif
```

This example is included in Backport4, Backport5, and Backport6.

If the original function name is unknown and only the 11-character export NID is
known, use a local alias and the raw-NID table. `backports.cpp` contains a
disabled example guarded by `BACKPORT_RAW_NID_EXAMPLE`; add the local export
name and target NID to `tools/nidmaps/libSceRtc.raw-nids.txt`:

```text
backportRawNid_ReplaceMe=AAAAAAAAAAA
```

Then build normally. The post-link step runs automatically for every build,
computes the temporary lld NID from `backportRawNid_ReplaceMe`, replaces it with
the target raw NID, and rebuilds the PRX `.hash` table.

To compile the disabled example itself:

```text
msbuild libSceRtc.sln /p:Configuration=Backport13 /p:Platform=Prospero /p:BackportExtraPreprocessorDefinitions=BACKPORT_RAW_NID_EXAMPLE
```

The generic runtime hook engine lives in `hooks.cpp`. Concrete backport hooks
live in `backport_hooks.cpp`. The module installs them from `module_start` and
removes them from `module_stop`. Add new problematic functions to the
`g_backportHooks[]` table and implement a matching `*_hook` replacement. Use
`hookGetOriginalFunction("symbol")` inside a hook when the replacement needs
to forward to the original trampoline.

For functions from modules loaded after this PRX, add entries to
`g_lateDlsymHooks[]`. These hooks are applied when later code resolves the
symbol with `sceKernelDlsym`; use `hookGetOriginalLateDlsymFunction("symbol")`
to forward to the resolved original. This path covers dynamic symbol resolution,
not static import relocations that were already bound by the loader.

## License

This project is licensed under the GNU General Public License v3.0. See
`LICENSE` for details.
