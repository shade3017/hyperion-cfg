# Hyperion CFG Reversal

`version-f0ea5da9412f4e35`

A teardown of the custom Control Flow Guard dispatcher Hyperion installs over the standard Windows CFG hooks — the bitmap check, the fallback/handler path that populates it, the memory-query based validation, and the PE load-config metadata showing the dispatcher isn't the compiler-emitted one.

> This is missing a fair bit of info by design — not every detail was fed in. Addresses are tied to the build above and will shift on new clients; read the structure, not the numbers.

## Dispatcher

The dispatcher is at `0x4c9360`. It takes the indirect target in `rax`, rejects addresses above the 47-bit limit, and tests one bit in an external bitmap.

```asm
4C9360  mov r11, 7FFFFFFFFFFFh
4C936A  cmp rax, r11
4C936D  ja  4C9395                  -> fallback
4C936F  mov r11, [EC2998]           -> bitmap base
4C9376  mov r10, rax
4C9379  shr r10, 0Fh
4C937D  movzx r11, byte [r11+r10]   -> bitmap byte
4C9382  mov r10, rax
4C9385  shr r10, 0Ch
4C9389  and r10, 7
4C938D  bt  r11, r10
4C9391  jnb 4C9395                  -> fallback
4C9393  jmp rax                     -> accepted target
4C9395  jmp 4C92E0                  -> fallback
```

For target `T` and bitmap base `B`:

```c
B = *(uint8_t **)0xec2998;

if (T <= 0x7FFFFFFFFFFF) {
    uint8_t byte = B[T >> 15];
    unsigned bit = (T >> 12) & 7;

    if ((byte >> bit) & 1)
        goto *T;
}

goto fallback;
```

There is no bitmap header or size field on this path. The layout is a pointer at `0xec2998` followed by direct indexing into an external byte array:

```
byte address = B + (T >> 15)
bit number   = (T >> 12) & 7
```

One bit covers a `0x1000`-byte target page; one bitmap byte covers eight pages, or `0x8000` of target address space. A flat array covering the accepted 47-bit span needs 2^32 addressable bytes, or 4 GiB. The committed size is separate from this addressable span.

The dumped slot contains `B = 0x1b81c430000`. For `T = 0x140001000`:

```
byte index = 0x140001000 >> 15       = 0x28000
bit index  = (0x140001000 >> 12) & 7 = 1
byte addr  = 0x1b81c430000 + 0x28000 = 0x1b81c458000
mask       = 1 << 1                   = 0x02
```

## Fallback

The fallback at `0x4c92e0` preserves the volatile integer registers and `xmm0`–`xmm5`. It calls the handler at `0x3dcc90` with:

```c
handler(target = rax, callsite_return_address = fallback_return_address);
```

The target is passed in `rcx`, and the fallback's return address is passed in `rdx`. When the handler returns, the trampoline restores the saved registers and executes `jmp rax`. Rejection does not use a Boolean return value; it goes through `NtTerminateProcess` at `0x3e0078`.

## Handler

The handler queries the target's memory metadata, sets bitmap bits for the returned region, and then decides whether execution may continue. Because it writes the same bitmap read by the dispatcher, a later indirect call can pass using bits populated by an earlier fallback.

Targets in `0x8000`–`0xffff` return immediately. They do not go through the memory query or bitmap population path. This does not bypass the dispatcher itself: execution still needs a set bit before the fallback can be entered.

The handler uses three native services:

| Syscall | RVA | Arguments | Purpose |
|---|---|---|---|
| `NtSetInformationProcess` | `0x3dd557` | `r10 = -1, rdx = 0x28, r8 = rsp+0xb0, r9 = 0x10` | Issued before the memory query. The return value is ignored. |
| `NtQueryVirtualMemory` | `0x3ddbc1` | `r10 = -1, rdx = T, r8 = 0, r9 = rsp+0xb0`, length `0x30` | Returns the memory-information record used for bitmap population and validation. |
| `NtTerminateProcess` | `0x3e0078` | `r10 = -1, rdx = 0xc0000141` | Rejects the target without returning to the fallback. |

The service numbers are `0x1c`, `0x23`, and `0x2c` after masking the garbage in the high bits of `eax`.

`NtQueryVirtualMemory` writes a `0x30`-byte `MEMORY_BASIC_INFORMATION` at `rsp+0xb0`:

| Offset | Field | Size | Use |
|---|---|---|---|
| `+0x00` | `BaseAddress` | 8 | Bitmap population and range comparisons. |
| `+0x08` | `AllocationBase` | 8 | Returned allocation base. |
| `+0x10` | `AllocationProtect` | 4 | Returned allocation protection. |
| `+0x14` | `PartitionId` | 4 | Partition identifier. |
| `+0x18` | `RegionSize` | 8 | Number of bytes covered by the bitmap loop. |
| `+0x20` | `State` | 4 | Compared with `MEM_COMMIT` (`0x1000`) at `0x3de174`. |
| `+0x24` | `Protect` | 4 | Tested against `0xf0` at `0x3de183`. |
| `+0x28` | `Type` | 4 | Compared with `MEM_IMAGE` (`0x1000000`) at `0x3de1bc`. |

A failed query does not stop the handler. It constructs this record instead:

```c
mbi.BaseAddress       = T & ~0xfff;
mbi.AllocationBase    = T & ~0xfff;
mbi.AllocationProtect = 0x40;
mbi.PartitionId       = 0;
mbi.RegionSize        = 0x1000;
mbi.State             = 0x1000;  // MEM_COMMIT
mbi.Protect           = 0x40;    // PAGE_EXECUTE_READWRITE
mbi.Type              = 0x20000; // MEM_MAPPED
```

The fallback record is therefore executable, committed, RWX, and `MEM_MAPPED`. It follows the non-image range checks rather than causing immediate rejection.

## Bitmap population

The handler reaches the bitmap slot through a computed address. Its base is `0xecf81e`, and the decoded displacement is `-0xce86`:

```
0xecf81e - 0xce86 = 0xec2998
```

The population loop adds the byte index to the pointer read from that slot, then sets the page bit atomically:

```asm
3DDE36  add rbp, [rdi+rsi]           -> [0xec2998] + byte index
3DDE3A  lock bts dword ptr [rbp], r12d
```

```c
for (uint64_t offset = 0; offset < mbi.RegionSize; offset += 0x1000) {
    uint64_t page = mbi.BaseAddress + offset;

    _InterlockedBitTestAndSet(
        (long *)(B + (page >> 15)),
        (page >> 12) & 7
    );
}
```

The loop sets bits but never clears them. A region size of `0x3001`, starting at bit 1, sets four consecutive page bits and produces byte `0x1e`.

Bitmap marking happens **before** the final validation decision. A set bit means the handler marked that page; it does not prove that the current invocation returned successfully. Rejection can happen after the bit is already set.

## Validation

The main checks are:

```asm
3DE174  cmp dword ptr [rsp+0d0], 1000h    -> State == MEM_COMMIT
3DE183  test byte ptr [rsp+0d4], 0f0h     -> executable Protect
3DE1BC  cmp dword ptr [rsp+0d8], 1000000h -> Type == MEM_IMAGE
3DE1C7  je  3DCD91                        -> normal return
```

Committed executable image memory returns normally. The protection test accepts `PAGE_EXECUTE`, `PAGE_EXECUTE_READ`, and `PAGE_EXECUTE_READWRITE`; RWX is not rejected here.

### Encoded range table (non-image, committed, executable)

For a committed executable non-image page, the handler walks ten encoded records. Each record is `0x18` bytes:

```c
struct encoded_range_record {
    uint64_t qword_00; // read at 0x3de55c
    uint64_t qword_08; // read at 0x3de561
    uint64_t qword_10; // read at 0x3de577; low dword also read at 0x3dead9
};
```

The record cursor starts at `0x10`, advances by `0x18`, and stops after cursor `0xe8`. Each record decodes to a lower and upper address bound. The comparison is:

```asm
3DEBFE  mov r10, [rsp+110h]  -> mbi.BaseAddress
3DEC06  cmp r10, rdx         -> decoded lower bound
3DEC09  setae r11b
3DEC0D  cmp r10, rax         -> decoded upper bound
3DEC10  setb r10b
3DEC14  and r10b, r11b
3DEC1B  je  3DEDD3           -> match
3DEE04  jmp 3DCD91           -> normal return
```

```c
decoded_lower <= mbi.BaseAddress && mbi.BaseAddress < decoded_upper
```

The lower bound is inclusive; the upper bound is exclusive. A constructed first record of `{0x40, 0, 0}` decodes to `[0, 0x2000)`: base `0` and base `0x1000` return, while base `0x2000` does not match. This constructed value demonstrates the encoding path; it is not a dumped live table entry.

The record-table address computed by the handler is `0x1b8105cd800`. Its contents are outside the module.

### Non-executable and non-committed pages

If `State != MEM_COMMIT` or `(Protect & 0xf0) == 0`, the handler goes to `0x3dec58` before checking `Type`. This path decodes a base `S` and applies another range test:

```c
if (T < S)
    goto reject;

if (T >= S + 0x93e1000)
    goto reject;

uint32_t delta = (uint32_t)T - (uint32_t)S;

if ((uint32_t)(delta + 0xf9a9d000) > 0xf9a9dfff)
    goto 0x3dcd91;

goto reject;
```

For page-aligned addresses, the accepted interval is:

```
S + 0x1000 <= T < S + 0x06563000
```

For this dump, `S = 0x7ff6d9080000`. `S` itself and `S + 0xfff` are rejected after page alignment. `S + 0x1000` and `S + 0x2000` return. The page at `S + 0x06563000` is rejected. This means `PAGE_READONLY` is not universally fatal; an address inside the special interval can still return.

If neither the image check nor an applicable range allows the target, the handler calls:

```c
NtTerminateProcess((HANDLE)-1, 0xc0000141);
```

## PE CFG metadata

The load-config directory is at `0xf23030` and has size `0x140`.

| Field | RVA | Value |
|---|---|---|
| `GuardCFCheckFunctionPointer` | `0xf230a0` | `0x10e9e10` |
| `GuardCFDispatchFunctionPointer` | `0xf230a8` | `0x10e9e20` |
| `GuardCFFunctionTable` | `0xf230b0` | `0` |
| `GuardCFFunctionCount` | `0xf230b8` | `0` |
| `GuardFlags` | `0xf230c0` | `0x100` |

The initial guard-dispatch slot contains the compiler stub at `0x383e80`, which is only `jmp rax`. The check stub at `0x8f60e0` returns immediately. **The dispatcher at `0x4c9360` is not the initial value in that slot** — it's installed over the compiler-emitted one.

The load config function table and count are zero, so this file does not carry the usual static table of valid CF targets.

---

*`version-f0ea5da9412f4e35`. Structure is the takeaway — addresses shift every build. This writeup is intentionally incomplete.*
