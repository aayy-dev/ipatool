# Running ipatool's App Store emulator on iOS 26 (jailbroken)

Since v2.4.0, ipatool signs App Store requests by emulating Apple's
StoreServices (SAP) code with [Unicorn](https://www.unicorn-engine.org/)
(a QEMU/TCG fork). The emulator is a **JIT**: it generates ARM64 machine code
at runtime and executes it. On a jailbroken **iOS 26** device (tested on
iPhone 11 / A13 / Dopamine) the stock iOS build crashed before it could run a
single translation block. This document explains why, and how this fork makes
it work.

TL;DR of the fix, all in `tools/patches/unicorn-ios.patch` plus a small Go
startup hook and a one-line build change:

1. Build Unicorn's **arm64** target (not x86).
2. Ask the jailbreak to mark the process **debugged** (`CS_DEBUGGED`) at
   startup so unsigned pages may execute.
3. Give the TCG a **split W^X** code buffer: write generated code through a
   writable mapping, execute it through a separate executable mapping of the
   same physical pages.

## Background: what iOS 26 forbids

Three independent kernel facts (verified on-device) kill the naive approaches:

- **W^X is unconditional.** On non-macOS XNU, `vm_map`/`vm_protect` reject any
  mapping that is simultaneously writable and executable. The code-signing
  bypass that would relax it is compiled only for macOS.
- **AMFI strips `max_protection`.** A plain anonymous `mmap(PROT_READ|WRITE)`
  has its *maximum* protection capped at RW, so a later
  `mprotect(..., PROT_EXEC)` exceeds `max_protection` and returns `EACCES`.
  This is a VM-layer failure, not a code-signing one — so `CS_DEBUGGED` does
  **not** fix it.
- **`MAP_JIT` is monitor-gated.** On A13 (PPL) `mmap(MAP_JIT)` needs a JIT
  entitlement that the code-signing monitor *honors*, read from a
  CoreTrust-validated signature. An ad-hoc `ldid` entitlement whose cdhash is
  merely in the jailbreak trust cache is **not** honored (the trust cache
  grants execution, not privileged entitlements). A paid developer account
  can't help either: `dynamic-codesigning` is a restricted Apple entitlement.

What a jailbreak *does* give you is `CS_DEBUGGED` (via Dopamine's
`jbctl proc_set_debugged`, which sets the pmap's `wx_allowed`): it lets
**unsigned/"invalid" pages execute**. Necessary, but not sufficient on its own.

## The fix

### 1. arm64 Unicorn (`tools/build-ios.sh`)

Upstream's SAP emulator became arm64, but the iOS build still compiled
Unicorn with `-DUNICORN_ARCH=x86`, so `uc_open(UC_ARCH_ARM64, ...)` returned
`UC_ERR_ARCH`. Changed to `-DUNICORN_ARCH=aarch64`.

### 2. Enable JIT at startup (`cmd/jit_ios.go`)

Before any command touches the emulator, ipatool runs
`jbctl proc_set_debugged <pid>` (jbctl is a jailbreak platform binary allowed
to set the flag). This sets `CS_DEBUGGED`/`wx_allowed` so the executable alias
below is allowed to run. No-op on non-iOS and harmless where jbctl is absent.

### 3. Split W^X in Unicorn's TCG (`tools/patches/unicorn-ios.patch`)

Unicorn 2.1.4 has no QEMU `splitwx` support, so it is ported here. The one
technique iOS 26 permits: create a fresh RWX-capable memory object with
`mach_make_memory_entry_64(MAP_MEM_NAMED_CREATE | VM_PROT_READ|WRITE|EXECUTE)`
and `vm_map` it **twice** — a writable (RW) alias and an executable (RX) alias
over the same pages. Code is written through RW and executed through RX;
neither alias is ever W+X, so the W^X ban never triggers, and the RX pages run
because the process is `CS_DEBUGGED`.

Porting that cleanly required:

- **Per-context offset.** `code_gen_splitwx_diff = rx - rw` is stored on each
  `TCGContext` (and copied to each `TranslationBlock` as `tb->splitwx_diff`
  for the jump patcher). It must be per-context, not global: the Store and SAP
  emulators run **concurrent** engines with different rw/rx gaps.
- **Right alias at each site.** `tb->tc.ptr`, `code_gen_prologue` and the
  `goto_ptr` epilogue use the RX alias; code generation writes through the RW
  alias (`to_rw(tc.ptr)`); `goto_tb` patching writes through the owning TB's RW
  alias; instruction-cache flushes target RX.
- **PC-relative materialization.** aarch64 `tcg_out_movi` loads near-PC 64-bit
  pointers (e.g. the `exit_tb` TranslationBlock pointer, which lives in the
  code buffer) with `ADR`/`ADRP`. Its displacement is computed against the
  **RX execution PC** (`code_ptr + diff`) so embedded absolute pointers resolve
  to their real value at run time instead of being shifted by `diff`. Same for
  far `tcg_out_goto_long` targets.
- **Free the RX alias on teardown.** Unicorn only `munmap`s the RW alias, so
  `free_code_gen_buffer` also unmaps the RX alias; otherwise repeated engines
  (e.g. the 2FA retry) leak address space and hit `KERN_NO_SPACE`. Do **not**
  `mach_port_deallocate` the memory-entry port (it breaks the live mappings on
  this kernel), and do **not** shrink `code_gen_buffer_size` (the large Store
  emulation overflows a small buffer).

The `dynamic-codesigning` entitlement in `resources/ios-entitlements.plist`
is kept as a belt-and-suspenders capability hint but is **not** load-bearing
on this jailbreak — `CS_DEBUGGED` is what actually permits execution.

## Notes

- Tested on iPhone 11, iOS 26 (Darwin 25), Dopamine. `ipatool auth login`
  (with 2FA) and `ipatool list-purchases` both work.
- `ipatool_jit_write_protect` is a no-op with split mappings (nothing to
  toggle).
- This is a jailbreak-only path: it relies on `CS_DEBUGGED`, which a stock
  device can't grant to a CLI tool.
