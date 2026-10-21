"""Live PE export lookup and two Enigma x64 anti-debug call handlers for IDA.

This module has no sample hash, image base, OEP, IAT, or Windows syscall-stub
bytes. Import it from an IDAPython debugger workflow; do not run it standalone.

Public interface (the debugger must be paused at ``entry_ea``):

* ``read_exact(ea, size) -> bytes`` reads debuggee memory.
* ``resolve_export(module_name, function) -> int`` resolves a loaded PE export,
  following standard PE forwarders without relying on IDA names or PDB files.
* ``resolve_ntsetinformationthread_entries() -> tuple[int, ...]`` returns the
  distinct loaded Nt/Zw export entry addresses.
* ``resolve_check_remote_debugger_present_entries() -> tuple[int, ...]`` returns
  distinct loaded kernel32/KernelBase export entry addresses. The kernel32
  export may forward to KernelBase and thus have the same address.
* ``emulate_ntsetinformationthread(entry_ea, protected_base, protected_size,
  *, hit_tid=None) -> dict`` intercepts ThreadHideFromDebugger (class 0x11).
* ``emulate_check_remote_debugger_present(entry_ea, protected_base,
  protected_size, *, hit_tid=None) -> dict`` returns BOOL success and stores
  FALSE in the API's output DWORD.
* ``emulate_nt_hide(base, image_size, tid) -> dict`` and
  ``emulate_check_remote(base, image_size, tid) -> dict`` are workflow-friendly
  wrappers. They verify the current RIP against resolved export entries.

Both handlers simulate a normal x64 ``ret`` at the API entry: they set RAX,
advance RSP by eight, and set RIP to the return address at [RSP]. They validate
the paused instruction, caller module, current thread, and relevant arguments
first. They raise RuntimeError on an unexpected call; the caller should leave
the process paused for inspection. Callers own breakpoints and resumption.
"""

from __future__ import annotations

import ida_dbg
import ida_idd


U64_LIMIT = 1 << 64


class ExportNotFound(LookupError):
    """A requested export or its containing loaded DLL is unavailable."""


def read_exact(ea: int, size: int) -> bytes:
    if not 0 <= ea < U64_LIMIT or size < 0 or ea + size > U64_LIMIT:
        raise ValueError(f"invalid debuggee read: 0x{ea:X} + 0x{size:X}")
    data = ida_idd.dbg_read_memory(ea, size)
    if data is None or len(data) != size:
        raise RuntimeError(f"unreadable debuggee memory: 0x{ea:X} + 0x{size:X}")
    return bytes(data)


def _write_exact(ea: int, expected: bytes, replacement: bytes) -> None:
    if len(expected) != len(replacement):
        raise ValueError("replacement must keep the same size")
    observed = read_exact(ea, len(expected))
    if observed != expected:
        raise RuntimeError(
            f"bytes changed at 0x{ea:X}: expected {expected.hex(' ')}, "
            f"observed {observed.hex(' ')}"
        )
    if expected == replacement:
        return
    if not ida_idd.dbg_write_memory(ea, replacement):
        raise RuntimeError(f"could not write debuggee memory at 0x{ea:X}")
    if read_exact(ea, len(replacement)) != replacement:
        raise RuntimeError(f"debuggee write did not persist at 0x{ea:X}")


def _module_basename(name: str) -> str:
    return name.replace("\\", "/").rsplit("/", 1)[-1].casefold()


def _module_at(ea: int) -> ida_idd.modinfo_t:
    info = ida_idd.modinfo_t()
    if not ida_dbg.get_module_info(ea, info):
        raise RuntimeError(f"no loaded module at 0x{ea:X}")
    return info


def _loaded_module(name: str) -> tuple[int, int, str]:
    requested = _module_basename(name)
    if not requested.endswith(".dll"):
        requested += ".dll"
    info = ida_idd.modinfo_t()
    found: list[tuple[int, int, str]] = []
    if ida_dbg.get_first_module(info):
        while True:
            if _module_basename(str(info.name)) == requested:
                found.append((int(info.base), int(info.size), str(info.name)))
            if not ida_dbg.get_next_module(info):
                break
    if not found:
        raise ExportNotFound(f"{requested} is not loaded")
    if len(found) != 1 or found[0][0] <= 0 or found[0][1] <= 0:
        raise RuntimeError(f"ambiguous loaded {requested}: {len(found)} module records")
    return found[0]


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _read_export_image(module_name: str) -> tuple[int, int, int, int, bytes]:
    base, loaded_size, path = _loaded_module(module_name)
    dos = read_exact(base, 0x40)
    if dos[:2] != b"MZ":
        raise RuntimeError(f"{path} has no DOS header in debuggee memory")
    pe_offset = _u32(dos, 0x3C)
    if pe_offset < 0x40 or pe_offset > min(loaded_size - 24, 0x100000):
        raise RuntimeError(f"invalid PE header offset for {path}")
    nt = read_exact(base + pe_offset, 24)
    if nt[:4] != b"PE\x00\x00" or _u16(nt, 4) != 0x8664:
        raise RuntimeError(f"{path} is not a loaded AMD64 PE")
    section_count, optional_size = _u16(nt, 6), _u16(nt, 20)
    if not 1 <= section_count <= 96 or optional_size < 120:
        raise RuntimeError(f"invalid PE header dimensions for {path}")
    optional = read_exact(base + pe_offset + 24, optional_size)
    if _u16(optional, 0) != 0x20B or _u32(optional, 108) < 1:
        raise RuntimeError(f"{path} has no PE32+ export directory")
    image_size = _u32(optional, 56)
    export_rva, export_size = _u32(optional, 112), _u32(optional, 116)
    if (
        image_size == 0
        or image_size > loaded_size
        or export_rva == 0
        or export_size < 40
        or export_size > 0x800000
        or export_rva + export_size > image_size
    ):
        raise RuntimeError(f"invalid loaded image/export bounds for {path}")
    section_offset = pe_offset + 24 + optional_size
    if section_offset + section_count * 40 > image_size:
        raise RuntimeError(f"section headers outside loaded {path}")
    sections = read_exact(base + section_offset, section_count * 40)
    return base, image_size, export_rva, export_size, sections


def _read_rva(base: int, image_size: int, rva: int, length: int) -> bytes:
    if rva <= 0 or length < 0 or rva + length > image_size:
        raise RuntimeError(f"RVA 0x{rva:X} + 0x{length:X} outside loaded image")
    return read_exact(base + rva, length) if length else b""


def _read_export_string(base: int, image_size: int, rva: int) -> str:
    result = bytearray()
    while len(result) < 256:
        if rva + len(result) >= image_size:
            raise RuntimeError("PE export string exceeds loaded image")
        address = base + rva + len(result)
        page_room = 0x1000 - (address & 0xFFF)
        chunk = _read_rva(
            base,
            image_size,
            rva + len(result),
            min(64, 256 - len(result), page_room, image_size - rva - len(result)),
        )
        end = chunk.find(b"\x00")
        if end >= 0:
            result.extend(chunk[:end])
            try:
                return result.decode("ascii")
            except UnicodeDecodeError as exc:
                raise RuntimeError("non-ASCII PE export name") from exc
        result.extend(chunk)
    raise RuntimeError("PE export name exceeds 256 bytes")


def _is_executable_rva(rva: int, sections: bytes) -> bool:
    for off in range(0, len(sections), 40):
        virtual_size = _u32(sections, off + 8)
        virtual_rva = _u32(sections, off + 12)
        raw_size = _u32(sections, off + 16)
        characteristics = _u32(sections, off + 36)
        if (
            virtual_rva <= rva < virtual_rva + max(virtual_size, raw_size)
            and characteristics & 0x20000000
        ):
            return True
    return False


def _resolve_export(
    module_name: str, function: str, seen: set[tuple[str, str]]
) -> int:
    module_name = _module_basename(module_name)
    if not module_name.endswith(".dll"):
        module_name += ".dll"
    key = (module_name, function)
    if key in seen or len(seen) >= 8:
        raise RuntimeError(f"cyclic/deep PE export forwarder at {module_name}!{function}")
    seen.add(key)

    base, image_size, export_rva, export_size, sections = _read_export_image(module_name)
    directory = _read_rva(base, image_size, export_rva, 40)
    ordinal_base = _u32(directory, 16)
    function_count = _u32(directory, 20)
    name_count = _u32(directory, 24)
    functions_rva = _u32(directory, 28)
    names_rva = _u32(directory, 32)
    ordinals_rva = _u32(directory, 36)
    if not 1 <= function_count <= 65536 or name_count > 65536:
        raise RuntimeError(f"invalid export table counts in {module_name}")
    functions = _read_rva(base, image_size, functions_rva, function_count * 4)
    if function.startswith("#"):
        try:
            index = int(function[1:]) - ordinal_base
        except ValueError as exc:
            raise RuntimeError(f"invalid forwarded ordinal {function}") from exc
    else:
        if name_count == 0:
            raise ExportNotFound(f"no named exports in {module_name}")
        name_rvas = _read_rva(base, image_size, names_rva, name_count * 4)
        ordinals = _read_rva(base, image_size, ordinals_rva, name_count * 2)
        lo, hi = 0, name_count
        while lo < hi:
            middle = (lo + hi) // 2
            candidate = _read_export_string(base, image_size, _u32(name_rvas, middle * 4))
            if candidate < function:
                lo = middle + 1
            else:
                hi = middle
        if (
            lo == name_count
            or _read_export_string(base, image_size, _u32(name_rvas, lo * 4))
            != function
        ):
            raise ExportNotFound(f"{module_name}!{function} absent from loaded exports")
        index = _u16(ordinals, lo * 2)
    if not 0 <= index < function_count:
        raise RuntimeError(f"invalid export ordinal for {module_name}!{function}")
    target_rva = _u32(functions, index * 4)
    if target_rva == 0 or target_rva >= image_size:
        raise RuntimeError(f"invalid export target for {module_name}!{function}")
    if export_rva <= target_rva < export_rva + export_size:
        forwarder = _read_export_string(base, image_size, target_rva)
        if "." not in forwarder:
            raise RuntimeError(f"malformed PE export forwarder {forwarder!r}")
        forwarded_module, forwarded_function = forwarder.rsplit(".", 1)
        if not forwarded_module or not forwarded_function:
            raise RuntimeError(f"malformed PE export forwarder {forwarder!r}")
        return _resolve_export(forwarded_module, forwarded_function, seen)
    if not _is_executable_rva(target_rva, sections):
        raise RuntimeError(f"{module_name}!{function} does not point to executable code")
    address = base + target_rva
    observed = _module_basename(str(_module_at(address).name))
    if observed != module_name:
        raise RuntimeError(
            f"export target 0x{address:X} belongs to {observed}, expected {module_name}"
        )
    read_exact(address, 1)
    return address


def resolve_export(module_name: str, function: str) -> int:
    """Resolve one named/ordinal export in the loaded 64-bit process image."""
    if not module_name or not function:
        raise ValueError("module_name and function are required")
    return _resolve_export(module_name, function, set())


def _distinct_entries(candidates: tuple[tuple[str, str], ...]) -> tuple[int, ...]:
    entries: set[int] = set()
    for module_name, function in candidates:
        try:
            entries.add(resolve_export(module_name, function))
        except ExportNotFound:
            continue
    if not entries:
        names = ", ".join(f"{mod}!{name}" for mod, name in candidates)
        raise ExportNotFound(f"no loaded API entry found for {names}")
    return tuple(sorted(entries))


def resolve_ntsetinformationthread_entries() -> tuple[int, ...]:
    """Find both Nt and Zw names, deduplicating aliases with the same address."""
    return _distinct_entries(
        (("ntdll.dll", "NtSetInformationThread"),
         ("ntdll.dll", "ZwSetInformationThread"))
    )


def resolve_check_remote_debugger_present_entries() -> tuple[int, ...]:
    """Find direct/forwarded kernel32 and KernelBase implementations."""
    return _distinct_entries(
        (("kernel32.dll", "CheckRemoteDebuggerPresent"),
         ("kernelbase.dll", "CheckRemoteDebuggerPresent"))
    )


def _reg(name: str) -> int:
    return int(ida_dbg.get_reg_val(name)) & (U64_LIMIT - 1)


def _call_context(
    entry_ea: int, protected_base: int, protected_size: int,
    hit_tid: int | None, allowed_modules: frozenset[str],
) -> dict[str, int]:
    if ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
        raise RuntimeError("debugger is not paused at the API entry")
    if hit_tid is not None and int(ida_dbg.get_current_thread()) != hit_tid:
        raise RuntimeError("the selected thread is not the breakpoint thread")
    if _reg("RIP") != entry_ea:
        raise RuntimeError(f"RIP does not match API entry 0x{entry_ea:X}")
    api_module = _module_basename(str(_module_at(entry_ea).name))
    if api_module not in allowed_modules:
        raise RuntimeError(f"API entry belongs to unexpected module {api_module}")
    if (
        protected_base <= 0 or protected_size <= 0
        or protected_base + protected_size > U64_LIMIT
    ):
        raise ValueError("invalid protected module extent")
    rsp = _reg("RSP")
    if rsp == 0 or rsp > U64_LIMIT - 8 or rsp & 7:
        raise RuntimeError(f"invalid API stack pointer 0x{rsp:X}")
    return_ea = int.from_bytes(read_exact(rsp, 8), "little")
    if not protected_base <= return_ea < protected_base + protected_size:
        raise RuntimeError(f"API caller 0x{return_ea:X} is outside protected module")
    caller_module = _module_at(return_ea)
    if int(caller_module.base) != protected_base:
        raise RuntimeError(f"API caller 0x{return_ea:X} belongs to another module")
    read_exact(return_ea, 1)
    return {"entry_ea": entry_ea, "return_ea": return_ea, "rsp": rsp,
            "thread_id": int(ida_dbg.get_current_thread())}


def _set_registers_or_restore(changes: tuple[tuple[str, int], ...]) -> None:
    originals = {name: _reg(name) for name, _ in changes}
    modified: list[str] = []
    try:
        for name, value in changes:
            if not ida_dbg.set_reg_val(name, value):
                raise RuntimeError(f"IDA refused to set {name}")
            modified.append(name)
            if _reg(name) != value:
                raise RuntimeError(f"IDA did not retain {name}=0x{value:X}")
    except Exception as exc:
        failed_restore: list[str] = []
        for name in reversed(modified):
            if not ida_dbg.set_reg_val(name, originals[name]):
                failed_restore.append(name)
        if failed_restore:
            raise RuntimeError(
                f"register update failed ({exc}); could not restore "
                + ", ".join(failed_restore)
            ) from exc
        raise


def _simulate_return(context: dict[str, int], result: int) -> None:
    _set_registers_or_restore(
        (("RAX", result), ("RSP", context["rsp"] + 8),
         ("RIP", context["return_ea"]))
    )


def emulate_ntsetinformationthread(
    entry_ea: int, protected_base: int, protected_size: int,
    *, hit_tid: int | None = None,
) -> dict[str, int]:
    """Suppress one validated ThreadHideFromDebugger call and return success."""
    context = _call_context(
        entry_ea, protected_base, protected_size, hit_tid, frozenset({"ntdll.dll"})
    )
    thread_handle = _reg("RCX")
    info_class = _reg("RDX")
    information = _reg("R8")
    information_length = _reg("R9")
    if info_class != 0x11:
        raise RuntimeError(f"NtSetInformationThread class is 0x{info_class:X}, not 0x11")
    if thread_handle == 0 or information != 0 or information_length != 0:
        raise RuntimeError(
            "unexpected ThreadHideFromDebugger arguments: "
            f"handle=0x{thread_handle:X} info=0x{information:X} "
            f"length=0x{information_length:X}"
        )
    _simulate_return(context, 0)  # STATUS_SUCCESS
    return {**context, "thread_handle": thread_handle,
            "information_class": info_class, "ntstatus": 0}


def emulate_check_remote_debugger_present(
    entry_ea: int, protected_base: int, protected_size: int,
    *, hit_tid: int | None = None,
) -> dict[str, int]:
    """Suppress one validated check; store FALSE and return BOOL success."""
    context = _call_context(
        entry_ea, protected_base, protected_size, hit_tid,
        frozenset({"kernel32.dll", "kernelbase.dll"}),
    )
    process_handle = _reg("RCX")
    output_ea = _reg("RDX")
    if process_handle == 0 or output_ea == 0:
        raise RuntimeError(
            f"unexpected CheckRemoteDebuggerPresent arguments: "
            f"handle=0x{process_handle:X} output=0x{output_ea:X}"
        )
    previous = read_exact(output_ea, 4)
    replacement = b"\x00" * 4
    _write_exact(output_ea, previous, replacement)
    try:
        _simulate_return(context, 1)  # BOOL TRUE: query succeeded
    except Exception:
        # If a register write failed, leave both output and registers as close
        # to their pre-call state as possible before the caller inspects them.
        _write_exact(output_ea, replacement, previous)
        raise
    return {**context, "process_handle": process_handle,
            "output_ea": output_ea, "previous_output": int.from_bytes(previous, "little"),
            "bool_result": 1}


def emulate_nt_hide(base: int, image_size: int, tid: int) -> dict[str, int]:
    """Emulate the loaded Nt/Zw ThreadHideFromDebugger API at the current RIP."""
    entry_ea = _reg("RIP")
    if entry_ea not in resolve_ntsetinformationthread_entries():
        raise RuntimeError(f"RIP 0x{entry_ea:X} is not a loaded Nt/ZwSetInformationThread export")
    return emulate_ntsetinformationthread(entry_ea, base, image_size, hit_tid=tid)


def emulate_check_remote(base: int, image_size: int, tid: int) -> dict[str, int]:
    """Emulate the loaded CheckRemoteDebuggerPresent API at the current RIP."""
    entry_ea = _reg("RIP")
    if entry_ea not in resolve_check_remote_debugger_present_entries():
        raise RuntimeError(
            f"RIP 0x{entry_ea:X} is not a loaded CheckRemoteDebuggerPresent export"
        )
    return emulate_check_remote_debugger_present(entry_ea, base, image_size, hit_tid=tid)
