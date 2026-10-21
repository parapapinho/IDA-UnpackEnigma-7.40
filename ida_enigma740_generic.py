"""Assisted Enigma Protector x64 7.40 OEP and pre-Scylla dump in IDA 9.4.

Run with File > Script file while the protected PE is open. With no debuggee,
the script launches IDA's Local Windows debugger. It also accepts a debuggee
paused at its *packed* entry point. Addresses and the image base are read from
this PE and the live process; neither sample hashes nor sample RVAs are used.

The observed v7.40 final-transfer instruction pattern is searched in live
memory. A section-relative HBP hint, seen in two v7.40 samples, also catches
the transfer if its code materializes after the last API stop. The hint alone
never confirms an OEP: the complete signature and uniqueness are checked at
execution. A missing or ambiguous pattern is reported, never guessed. The script
intercepts only calls made by the protected module to the two known APIs. It
does not change system DLL code or the protected file on disk. The output is
an intermediate mapped-layout PE; Scylla must still rebuild its imports.

Console controls: ``enigma740_generic.status()``, ``advance()``, ``probe_jump()``,
``confirm_oep()``, ``confirm_manual_oep(jump_ea, target_ea)``,
``set_bss_rva(rva)``, ``save()``, and ``abort()``. Set AUTO_CONTINUE=False to inspect each recognized stop before
calling ``advance()``.
"""

from __future__ import annotations

import builtins
import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import ida_dbg
import ida_idd
import ida_kernwin
import ida_nalt


AUTO_CONTINUE = True
BSS_RVA: int | None = None  # Optional explicit uninitialized section start.
MAX_CAPTURE_SIZE = 0x20000000  # A 512 MiB cap on a single IDA Python capture.
TEMPLATE_JUMP_OFFSET = 0x44F80  # Observed from the first appended section in two v7.40 samples.
PAGE_SIZE = 0x1000
CHUNK_SIZE = 0x10000
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

print("[Enigma 7.40 generic] loading workflow; companions must be in " + str(SCRIPT_DIR))
try:
    import enigma740_generic_core as core  # noqa: E402
    import ida_enigma740_api as api  # noqa: E402
except Exception as exc:
    ida_kernwin.warning(
        "Enigma 7.40: nao foi possivel carregar os arquivos auxiliares em "
        + str(SCRIPT_DIR) + "\n" + str(exc)
    )
    raise


def _basename(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1].casefold()


def _module_at(ea: int) -> ida_idd.modinfo_t:
    info = ida_idd.modinfo_t()
    if not ida_dbg.get_module_info(ea, info):
        raise RuntimeError(f"no loaded module at 0x{ea:X}")
    return info


def _read_live_pe(base: int, disk_pe: dict) -> dict:
    size = disk_pe["size_of_headers"]
    if size < 0x200 or size > 0x100000:
        raise RuntimeError(f"unexpected PE header size 0x{size:X}")
    live = core.parse_pe(api.read_exact(base, size))
    if (live["entry_rva"] != disk_pe["entry_rva"]
            or live["size_of_image"] != disk_pe["size_of_image"]
            or [s["rva"] for s in live["sections"]]
            != [s["rva"] for s in disk_pe["sections"]]):
        raise RuntimeError("loaded PE headers differ from the protected file")
    return live


def _capture_image(base: int, size: int) -> tuple[bytes, list[dict]]:
    if not 0 < size <= MAX_CAPTURE_SIZE:
        raise RuntimeError(f"image size 0x{size:X} exceeds capture limit")
    image = bytearray(size)
    unreadable = []
    for start in range(0, size, CHUNK_SIZE):
        length = min(CHUNK_SIZE, size - start)
        data = ida_idd.dbg_read_memory(base + start, length)
        if data is not None and len(data) == length:
            image[start : start + length] = data
            continue
        for page in range(start, start + length, PAGE_SIZE):
            n = min(PAGE_SIZE, size - page)
            data = ida_idd.dbg_read_memory(base + page, n)
            if data is not None and len(data) == n:
                image[page : page + n] = data
            else:
                unreadable.append({"rva": page, "size": n})
    return bytes(image), unreadable


def _section_at(sections: list[dict], rva: int) -> dict | None:
    for sec in sections:
        if sec["rva"] <= rva < sec["rva"] + max(sec["virtual_size"], sec["raw_size"]):
            return sec
    return None


def _original_section_limit(sections: list[dict]) -> int:
    resources = [s["index"] for s in sections if s["name"].casefold() == ".rsrc"]
    return max(resources) + 1 if resources else len(sections) - 2


def _loaded_module_ranges() -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    info = ida_idd.modinfo_t()
    if ida_dbg.get_first_module(info):
        while True:
            if int(info.base) > 0 and int(info.size) > 0:
                ranges.append((int(info.base), int(info.size), str(info.name)))
            if not ida_dbg.get_next_module(info):
                break
    return ranges


class Workflow(ida_dbg.DBG_Hooks):
    _enigma_workflow_token = "ida-enigma740-generic-v1"

    def __init__(self, auto: bool = True, bss_rva: int | None = None):
        super().__init__()
        self.auto = bool(auto)
        self.bss_rva = bss_rva
        self.phase = "new"
        self.base: int | None = None
        self.pe: dict | None = None
        self.disk_pe: dict | None = None
        self.disk_blob: bytes | None = None
        self.input_path: Path | None = None
        self.module_name: str | None = None
        self.main_tid: int | None = None
        self.owned_bpts: dict[int, str] = {}
        self.nt_entries: set[int] = set()
        self.check_entries: set[int] = set()
        self.jump: dict | None = None
        self.jump_hit_tid: int | None = None
        self.oep_candidate: int | None = None
        self.oep: int | None = None
        self.oep_source: str | None = None
        self.api_resume_phase: str | None = None
        self.pending_step: tuple[int, str, str] | None = None
        self.events: list[dict] = []
        self.failure: str | None = None
        self.nt_hide_count = 0
        self.check_count = 0
        self.scan_count = 0
        self.rejected_hint = False
        self.save_prompt_queued = False

    def _log(self, event: str, **details: object) -> None:
        self.events.append({"event": event, **details})
        suffix = " ".join(f"{key}={value}" for key, value in details.items())
        print("[Enigma 7.40 generic] " + event + (" " + suffix if suffix else ""))

    def _require_paused(self) -> None:
        if ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
            raise RuntimeError("pause the Local Windows debugger first")

    def _require_bound(self) -> tuple[int, dict]:
        if self.base is None or self.pe is None:
            raise RuntimeError("the protected module has not been bound")
        return self.base, self.pe

    def _add_hbp(self, ea: int, purpose: str) -> None:
        if ea in self.owned_bpts:
            return
        if ida_dbg.exist_bpt(ea):
            raise RuntimeError(f"an existing breakpoint occupies 0x{ea:X}")
        if not ida_dbg.add_bpt(ea, 1, ida_idd.BPT_EXEC):
            raise RuntimeError(f"could not allocate hardware execution breakpoint at 0x{ea:X}")
        self.owned_bpts[ea] = purpose
        self._log("HBP armed", address=f"0x{ea:X}", purpose=purpose)

    def _del_hbp(self, ea: int) -> None:
        if ea not in self.owned_bpts:
            return
        if not ida_dbg.del_bpt(ea):
            raise RuntimeError(f"could not remove owned HBP at 0x{ea:X}")
        del self.owned_bpts[ea]

    def _resume(self) -> None:
        if not ida_dbg.request_continue_process():
            raise RuntimeError("IDA refused to resume the process")
        ida_dbg.run_requests()

    def _step_into(self) -> None:
        if not ida_dbg.request_step_into():
            raise RuntimeError("IDA refused to single-step")
        ida_dbg.run_requests()

    def _bind(self, base: int, module_size: int, name: str) -> None:
        if self.disk_pe is None or self.input_path is None:
            raise RuntimeError("protected file was not validated")
        if base <= 0 or base & 0xFFFF:
            raise RuntimeError(f"invalid loaded module base 0x{base:X}")
        if _basename(name) != self.input_path.name.casefold():
            raise RuntimeError(f"debuggee {name!r} is not {self.input_path.name!r}")
        live = _read_live_pe(base, self.disk_pe)
        if module_size and live["size_of_image"] > module_size:
            raise RuntimeError("live SizeOfImage exceeds the debugger module extent")
        self.base, self.pe, self.module_name = base, live, name
        self._log("protected module", name=name, base=f"0x{base:X}",
                  packed_ep=f"0x{base + live['entry_rva']:X}",
                  size=f"0x{live['size_of_image']:X}")

    def _arm_apis(self) -> None:
        base, pe = self._require_bound()
        self._require_paused()
        rip = int(ida_dbg.get_reg_val("RIP"))
        if rip != base + pe["entry_rva"]:
            raise RuntimeError(f"expected packed entry at 0x{base + pe['entry_rva']:X}; RIP=0x{rip:X}")
        self.main_tid = int(ida_dbg.get_current_thread())
        nt = api.resolve_ntsetinformationthread_entries()
        try:
            check = api.resolve_check_remote_debugger_present_entries()
        except api.ExportNotFound as exc:
            check = ()
            self._log("optional debugger API unavailable", detail=str(exc))
        # Reserve DR slots for the final jump and its OEP target. Nt/Zw and
        # kernel32/KernelBase are normally aliases; if distinct, monitor the
        # primary export and report the uncovered alternative explicitly.
        try:
            nt_primary = api.resolve_export("ntdll.dll", "NtSetInformationThread")
        except api.ExportNotFound:
            nt_primary = nt[0]
        self._add_hbp(nt_primary, "nt")
        self.nt_entries.add(nt_primary)
        if len(nt) > 1:
            self._log("distinct Nt/Zw aliases; only primary entry monitored",
                      monitored=f"0x{nt_primary:X}",
                      other=[f"0x{ea:X}" for ea in nt if ea != nt_primary])
        try:
            check_primary = api.resolve_export("kernel32.dll", "CheckRemoteDebuggerPresent")
        except api.ExportNotFound:
            check_primary = check[0] if check else None
        if check_primary is not None:
            try:
                self._add_hbp(check_primary, "check")
                self.check_entries.add(check_primary)
            except RuntimeError as exc:
                self._log("optional check breakpoint unavailable", address=f"0x{check_primary:X}", error=str(exc))
        if len(check) > 1:
            self._log("distinct check API aliases; only primary entry monitored",
                      monitored=f"0x{check_primary:X}" if check_primary is not None else None,
                      other=[f"0x{ea:X}" for ea in check if ea != check_primary])
        self.phase = "ready"
        self._log("APIs armed", nt=len(self.nt_entries), check=len(self.check_entries))
        self.probe_jump(raise_on_ambiguity=False)
        if self.auto:
            self._resume()

    def _arm_template_hint(self) -> None:
        """Use a version-specific location only as a speculative execution trigger."""
        base, pe = self._require_bound()
        if (self.jump is not None or self.rejected_hint
                or "hint" in self.owned_bpts.values()):
            return
        limit = _original_section_limit(pe["sections"])
        if not 0 <= limit < len(pe["sections"]):
            return
        first = pe["sections"][limit]
        if (not first["characteristics"] & 0x20000000
                or TEMPLATE_JUMP_OFFSET >= max(first["virtual_size"], first["raw_size"])):
            return
        hint_ea = base + first["rva"] + TEMPLATE_JUMP_OFFSET
        try:
            self._add_hbp(hint_ea, "hint")
        except RuntimeError as exc:
            self._log("optional transfer hint unavailable", address=f"0x{hint_ea:X}", error=str(exc))
            return
        self._log("speculative v7.40 transfer hint armed", address=f"0x{hint_ea:X}",
                  section_index=first["index"], offset=f"0x{TEMPLATE_JUMP_OFFSET:X}")

    def start(self) -> "Workflow":
        name = ida_nalt.get_input_file_path()
        if not name:
            raise RuntimeError("IDA has no protected input file")
        path = Path(name)
        if not path.is_file():
            raise RuntimeError(f"protected input file is missing: {path}")
        self.input_path = path
        self.disk_blob = path.read_bytes()
        self.disk_pe = core.parse_pe(self.disk_blob)
        if self.disk_pe["size_of_image"] > MAX_CAPTURE_SIZE:
            raise RuntimeError("protected image exceeds this workflow's capture limit")
        state = ida_dbg.get_process_state()
        if state == ida_dbg.DSTATE_RUN:
            raise RuntimeError("debuggee is running; pause it at the packed entry point")
        if state not in (ida_dbg.DSTATE_NOTASK, ida_dbg.DSTATE_SUSP):
            raise RuntimeError(f"unexpected debugger state {state}")
        if state == ida_dbg.DSTATE_NOTASK and not ida_dbg.load_debugger("win32", False):
            raise RuntimeError("could not select IDA Local Windows debugger")
        if not self.hook():
            raise RuntimeError("could not install IDA debugger event hook")
        try:
            if state == ida_dbg.DSTATE_NOTASK:
                self.phase = "await_process_start"
                result = ida_dbg.request_start_process(str(path), None, str(path.parent))
                if result is False or result <= 0:
                    raise RuntimeError("IDA refused to start the protected process")
                self._log("starting Local Windows debugger", file=str(path))
                ida_dbg.run_requests()
            else:
                rip = int(ida_dbg.get_reg_val("RIP"))
                module = _module_at(rip)
                self._bind(int(module.base), int(module.size), str(module.name))
                self._arm_apis()
        except Exception:
            self._cleanup()
            raise
        return self

    def dbg_process_start(
        self, pid: int, tid: int, ea: int, modinfo_name: str,
        modinfo_base: int, modinfo_size: int,
    ) -> None:
        if self.phase != "await_process_start":
            return
        try:
            self._bind(int(modinfo_base), int(modinfo_size), str(modinfo_name))
            self.main_tid = tid
            base, pe = self._require_bound()
            packed_ep = base + pe["entry_rva"]
            if ea == packed_ep and ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP:
                self._arm_apis()
                return
            self._add_hbp(packed_ep, "packed_ep")
            self.phase = "await_packed_ep"
            self._log("running to protected entry", address=f"0x{packed_ep:X}")
            self._resume()
        except Exception as exc:
            self._fail(exc)

    def dbg_process_exit(self, pid: int, tid: int, ea: int, exit_code: int) -> None:
        self._log("process exited", code=exit_code, phase=self.phase)
        self.phase = "exited"
        self.owned_bpts.clear()
        self.unhook()

    def dbg_request_error(self, failed_command: int, failed_dbg_notification: int) -> None:
        self._fail(RuntimeError(
            f"IDA debugger request failed: command={failed_command}, "
            f"notification={failed_dbg_notification}"
        ))

    def _fail(self, exc: Exception) -> None:
        self.failure = str(exc)
        self.phase = "failed"
        self._log("STOPPED for inspection", error=self.failure)
        self._cleanup()

    def _cleanup(self) -> None:
        for ea in tuple(self.owned_bpts):
            try:
                self._del_hbp(ea)
            except Exception as exc:
                self._log("breakpoint cleanup failed", address=f"0x{ea:X}", error=str(exc))
        self.unhook()

    def abort(self) -> None:
        self._require_paused()
        self._cleanup()
        self.phase = "aborted"
        self._log("aborted; process remains paused")

    def status(self) -> dict:
        info = {
            "phase": self.phase,
            "base": f"0x{self.base:X}" if self.base is not None else None,
            "packed_ep": (
                f"0x{self.base + self.pe['entry_rva']:X}"
                if self.base is not None and self.pe is not None else None
            ),
            "jump": f"0x{self.base + self.jump['rva']:X}"
                    if self.base is not None and self.jump else None,
            "oep_candidate": f"0x{self.oep_candidate:X}" if self.oep_candidate else None,
            "oep": f"0x{self.oep:X}" if self.oep else None,
            "oep_source": self.oep_source,
            "nt_hide_count": self.nt_hide_count,
            "check_count": self.check_count,
            "scan_count": self.scan_count,
            "owned_hbps": {f"0x{ea:X}": purpose for ea, purpose in self.owned_bpts.items()},
            "failure": self.failure,
        }
        self._log("status", **info)
        return info

    def _return_into_protected_module(self) -> bool:
        base, pe = self._require_bound()
        rsp = int(ida_dbg.get_reg_val("RSP"))
        ret = int.from_bytes(api.read_exact(rsp, 8), "little")
        if not base <= ret < base + pe["size_of_image"]:
            return False
        sec = _section_at(pe["sections"], ret - base)
        return (int(_module_at(ret).base) == base and sec is not None
                and bool(sec["characteristics"] & 0x20000000))

    def _pass_other_call(self, ea: int, kind: str) -> None:
        # Keeping a HBP at this API entry while resuming would immediately
        # retrigger it. Execute the first instruction without that HBP, then
        # rearm in dbg_step_into before allowing this unrelated call to run.
        self._del_hbp(ea)
        self.pending_step = (ea, kind, self.api_resume_phase or "ready")
        self.api_resume_phase = None
        self.phase = "await_api_step"
        self._step_into()

    def dbg_step_into(self) -> None:
        if self.phase != "await_api_step" or self.pending_step is None:
            return
        try:
            ea, kind, resume_phase = self.pending_step
            if int(ida_dbg.get_reg_val("RIP")) == ea:
                raise RuntimeError("single-step did not advance past API entry")
            self._add_hbp(ea, kind)
            self.pending_step = None
            self.phase = resume_phase
            self._log("unrelated API call allowed", kind=kind, next_rip=f"0x{int(ida_dbg.get_reg_val('RIP')):X}")
            self._resume()
        except Exception as exc:
            self._fail(exc)

    def probe_jump(self, *, raise_on_ambiguity: bool = True) -> dict | None:
        """Search currently materialized code for the unique v7.40 transfer."""
        self._require_paused()
        base, pe = self._require_bound()
        if self.jump is not None:
            return self.jump
        self.scan_count += 1
        image, unreadable = _capture_image(base, pe["size_of_image"])
        try:
            # A missing page could hide another match. Only a fully readable
            # appended tail can prove that the signature is unique.
            limit = _original_section_limit(pe["sections"])
            for sec in pe["sections"][limit:]:
                lo = sec["rva"]
                hi = lo + max(sec["virtual_size"], sec["raw_size"])
                if any(hole["rva"] < hi and lo < hole["rva"] + hole["size"]
                       for hole in unreadable):
                    raise ValueError(f"unreadable page in appended section {sec['index']}")
            jump = core.find_final_jump(image, pe["sections"])
        except ValueError as exc:
            self._log("final transfer not yet unique", attempt=self.scan_count,
                      unreadable_pages=len(unreadable), detail=str(exc))
            self._arm_template_hint()
            if raise_on_ambiguity:
                raise RuntimeError(str(exc)) from exc
            return None
        jump_ea = base + jump["rva"]
        if api.read_exact(jump_ea - 8, len(core.FINAL_TRANSFER)) != core.FINAL_TRANSFER:
            raise RuntimeError("final transfer changed between scan and HBP placement")
        for ea, purpose in tuple(self.owned_bpts.items()):
            if purpose == "hint":
                self._del_hbp(ea)
        self._add_hbp(jump_ea, "jump")
        self.jump = jump
        self._log("live final transfer found", address=f"0x{jump_ea:X}",
                  signature_rva=f"0x{jump['hits'][0]['signature_rva']:X}",
                  section_anchor=jump["section_anchor"])
        return jump

    def _on_template_hint(self, tid: int, bptea: int) -> None:
        """Confirm a speculative hit using the full live signature and scan."""
        self._del_hbp(bptea)
        if api.read_exact(bptea - 8, len(core.FINAL_TRANSFER)) != core.FINAL_TRANSFER:
            self.rejected_hint = True
            self._log("transfer hint rejected: bytes differ", address=f"0x{bptea:X}")
            self.probe_jump(raise_on_ambiguity=False)
            if self.auto:
                self._resume()
            return
        jump = self.probe_jump(raise_on_ambiguity=True)
        if jump is None or self.base + jump["rva"] != bptea:
            raise RuntimeError("transfer hint does not match the unique live final jump")
        self._log("transfer hint confirmed by complete live signature", address=f"0x{bptea:X}")
        self._on_jump(tid, bptea)

    def _validate_oep_target(self, jump_ea: int, target: int) -> dict:
        base, pe = self._require_bound()
        if not base <= target < base + pe["size_of_image"]:
            raise RuntimeError(f"jmp rax target 0x{target:X} is outside the protected module")
        if int(_module_at(target).base) != base:
            raise RuntimeError("jmp rax target belongs to a different module")
        target_rva = target - base
        target_section = _section_at(pe["sections"], target_rva)
        jump_section = _section_at(pe["sections"], jump_ea - base)
        limit = _original_section_limit(pe["sections"])
        if (target_section is None or jump_section is None
                or target_section["index"] >= limit
                or jump_section["index"] < limit
                or not target_section["characteristics"] & 0x20000000):
            raise RuntimeError("transfer is not from appended Enigma code to an earlier executable application section")
        first = api.read_exact(target, 16)
        if first == b"\x00" * 16 or first == b"\xCC" * 16:
            raise RuntimeError("target bytes are blank or breakpoint filler")
        disk_differs = None
        if self.disk_blob is not None:
            within = target_rva - target_section["rva"]
            if within + 16 <= target_section["raw_size"]:
                disk_off = target_section["raw_offset"] + within
                if disk_off + 16 <= len(self.disk_blob):
                    disk_differs = self.disk_blob[disk_off : disk_off + 16] != first
        return {"target_rva": target_rva,
                "target_section": target_section["index"],
                "jump_section": jump_section["index"],
                "first_16_bytes": first.hex(),
                "bytes_differ_from_packed_file": disk_differs}

    def _on_jump(self, tid: int, bptea: int) -> None:
        base, _ = self._require_bound()
        if self.jump is None or bptea != base + self.jump["rva"]:
            raise RuntimeError("final jump breakpoint does not match discovered transfer")
        if api.read_exact(bptea - 8, len(core.FINAL_TRANSFER)) != core.FINAL_TRANSFER:
            raise RuntimeError("final jump bytes changed before execution")
        target = int(ida_dbg.get_reg_val("RAX")) & ((1 << 64) - 1)
        evidence = self._validate_oep_target(bptea, target)
        self.oep_candidate = target
        self.jump_hit_tid = tid
        self.oep_source = "observed_live_signature_hbp"
        self.phase = "at_jump"
        self._log("final jmp rax reached", tid=tid, jump=f"0x{bptea:X}",
                  target=f"0x{target:X}", **evidence)
        if self.auto:
            self.advance()

    def dbg_bpt(self, tid: int, bptea: int) -> int:
        kind = self.owned_bpts.get(bptea)
        if kind is None:
            return 0  # User breakpoint: leave suspended for inspection.
        try:
            rip = int(ida_dbg.get_reg_val("RIP"))
            if rip != bptea:
                raise RuntimeError(f"HBP at 0x{bptea:X}, but RIP=0x{rip:X}")
            if kind == "packed_ep" and self.phase == "await_packed_ep":
                self._del_hbp(bptea)
                self._log("protected entry reached", address=f"0x{bptea:X}", tid=tid)
                self._arm_apis()
            elif kind in ("nt", "check"):
                self.api_resume_phase = self.phase
                self.phase = "at_api"
                self._log("API breakpoint", kind=kind, tid=tid, address=f"0x{bptea:X}",
                          rcx=f"0x{int(ida_dbg.get_reg_val('RCX')) & ((1 << 64)-1):X}",
                          rdx=f"0x{int(ida_dbg.get_reg_val('RDX')) & ((1 << 64)-1):X}")
                if self.auto:
                    self.advance()
            elif kind == "jump":
                self._on_jump(tid, bptea)
            elif kind == "hint":
                self._on_template_hint(tid, bptea)
            elif kind == "oep":
                if tid != self.jump_hit_tid or bptea != self.oep_candidate:
                    raise RuntimeError("OEP HBP was hit by an unexpected thread or address")
                self.phase = "at_oep_candidate"
                self._log("OEP candidate reached", tid=tid, address=f"0x{bptea:X}")
                if self.auto:
                    self.confirm_oep()
            else:
                raise RuntimeError(f"unexpected HBP {kind} in phase {self.phase}")
        except Exception as exc:
            self._fail(exc)
        return 0

    def advance(self) -> None:
        """Process the current API/jump stop, or resume from the packed EP."""
        self._require_paused()
        if self.phase == "ready":
            self._resume()
            return
        if self.phase == "at_api":
            base, pe = self._require_bound()
            ea = int(ida_dbg.get_reg_val("RIP"))
            kind = self.owned_bpts.get(ea)
            if kind not in ("nt", "check"):
                raise RuntimeError("selected thread is not paused at an owned API HBP")
            if not self._return_into_protected_module():
                self._log("API call outside protected module", kind=kind, address=f"0x{ea:X}")
                self._pass_other_call(ea, kind)
                return
            tid = int(ida_dbg.get_current_thread())
            if kind == "nt" and int(ida_dbg.get_reg_val("RDX")) != 0x11:
                self._log("NtSetInformationThread class is not ThreadHideFromDebugger",
                          information_class=f"0x{int(ida_dbg.get_reg_val('RDX')):X}")
                self._pass_other_call(ea, kind)
                return
            if kind == "check" and (int(ida_dbg.get_reg_val("RCX")) & ((1 << 64) - 1)) != (1 << 64) - 1:
                self._log("CheckRemoteDebuggerPresent handle is not current-process pseudohandle",
                          handle=f"0x{int(ida_dbg.get_reg_val('RCX')) & ((1 << 64)-1):X}")
                self._pass_other_call(ea, kind)
                return
            result = (api.emulate_nt_hide(base, pe["size_of_image"], tid)
                      if kind == "nt" else api.emulate_check_remote(base, pe["size_of_image"], tid))
            if kind == "nt":
                self.nt_hide_count += 1
                self._log("ThreadHideFromDebugger suppressed", tid=tid,
                          return_address=f"0x{result['return_ea']:X}")
            else:
                self.check_count += 1
                self._log("CheckRemoteDebuggerPresent returned FALSE", tid=tid,
                          output=f"0x{result['output_ea']:X}",
                          return_address=f"0x{result['return_ea']:X}")
            self.phase = self.api_resume_phase or "ready"
            self.api_resume_phase = None
            if self.jump is None and self.oep is None:
                self.probe_jump(raise_on_ambiguity=False)
            self._resume()
            return
        if self.phase == "at_jump":
            if self.oep_candidate is None or self.jump is None or self.base is None:
                raise RuntimeError("no validated jump target")
            if int(ida_dbg.get_reg_val("RIP")) != self.base + self.jump["rva"]:
                raise RuntimeError("RIP moved away from the validated final jump")
            self._del_hbp(self.base + self.jump["rva"])
            self._add_hbp(self.oep_candidate, "oep")
            self.phase = "await_oep"
            self._resume()
            return
        if self.phase == "at_oep_candidate":
            self.confirm_oep()
            return
        raise RuntimeError(f"no action available in phase {self.phase}")

    def _require_confirmed_oep(self) -> tuple[int, dict, int]:
        self._require_paused()
        base, pe = self._require_bound()
        if self.oep is None or int(ida_dbg.get_reg_val("RIP")) != self.oep:
            raise RuntimeError("debugger is not paused at the confirmed OEP")
        if self.jump_hit_tid is not None and int(ida_dbg.get_current_thread()) != self.jump_hit_tid:
            raise RuntimeError("select the thread that reached the OEP")
        return base, pe, self.oep - base

    def confirm_oep(self) -> int:
        """Confirm the observed jump reached its target; optionally queue Save As."""
        self._require_paused()
        if self.oep_candidate is None or self.jump_hit_tid is None or self.jump is None:
            raise RuntimeError("first observe the unique final jump and its target")
        if int(ida_dbg.get_current_thread()) != self.jump_hit_tid:
            raise RuntimeError("select the thread that executed the final jump")
        rip = int(ida_dbg.get_reg_val("RIP"))
        if rip != self.oep_candidate:
            raise RuntimeError(f"RIP=0x{rip:X}; expected jump target 0x{self.oep_candidate:X}")
        self._validate_oep_target(self.base + self.jump["rva"], rip)
        self._del_hbp(rip)
        self.oep = rip
        self.phase = "at_oep"
        self._log("OEP confirmed", va=f"0x{rip:X}", rva=f"0x{rip-self.base:X}")
        if self.auto:
            self._queue_save_prompt()
        return rip

    def confirm_manual_oep(self, jump_ea: int, target_ea: int) -> int:
        """Accept a user-observed ``jmp rax`` after a manual single-step.

        Call while paused on the target's first instruction. The report labels
        this as a manual assertion because this hook did not observe the jump.
        """
        self._require_paused()
        base, pe = self._require_bound()
        rip = int(ida_dbg.get_reg_val("RIP"))
        if rip != target_ea:
            raise RuntimeError(f"RIP=0x{rip:X}, not supplied target 0x{target_ea:X}")
        if int(ida_dbg.get_reg_val("RAX")) & ((1 << 64) - 1) != target_ea:
            raise RuntimeError("RAX no longer contains the supplied jump target")
        if not base <= jump_ea < base + pe["size_of_image"]:
            raise RuntimeError("supplied jump is outside the protected image")
        if api.read_exact(jump_ea, 2) != b"\xFF\xE0":
            raise RuntimeError("supplied source is not jmp rax (FF E0)")
        evidence = self._validate_oep_target(jump_ea, target_ea)
        for ea, purpose in tuple(self.owned_bpts.items()):
            if purpose in ("jump", "hint", "oep"):
                self._del_hbp(ea)
        self.oep_candidate = None
        self.jump_hit_tid = None
        self.jump = {"rva": jump_ea - base, "hits": [],
                     "section_anchor": "manually_observed_jmp_rax"}
        self.jump_hit_tid = int(ida_dbg.get_current_thread())
        self.oep_candidate = target_ea
        self.oep_source = "manual_single_step_assertion"
        self._log("manual OEP transfer asserted", jump=f"0x{jump_ea:X}",
                  target=f"0x{target_ea:X}", **evidence)
        return self.confirm_oep()

    def _default_path(self) -> Path:
        assert self.input_path is not None
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        stem = f"{self.input_path.stem}_pre_scylla_{stamp}_{uuid.uuid4().hex[:8]}"
        return self.input_path.parent / f"{stem}.exe"

    @staticmethod
    def _output_paths(prepared_path: Path) -> tuple[Path, Path, Path]:
        return prepared_path, prepared_path.with_suffix(".mem.bin"), prepared_path.with_suffix(".json")

    def _choose_path(self) -> Path | None:
        chosen = ida_kernwin.ask_file(
            True, str(self._default_path()),
            "Salvar dump Enigma 7.40 anterior ao Scylla (.exe)",
        )
        if not chosen:
            return None
        path = Path(chosen).expanduser().absolute()
        if path.suffix.casefold() != ".exe":
            raise ValueError("o arquivo escolhido precisa terminar em .exe")
        if not path.parent.is_dir():
            raise ValueError("a pasta escolhida não existe")
        for output in self._output_paths(path):
            if output.exists() or output.is_symlink():
                raise FileExistsError(f"arquivo já existe: {output}; escolha outro nome")
        return path

    def _select_bss_rva(self, pe: dict) -> tuple[int | None, str]:
        if self.bss_rva is not None:
            if not isinstance(self.bss_rva, int) or self.bss_rva < 0:
                raise ValueError("bss_rva must be a nonnegative section RVA")
            selected = next((s for s in pe["sections"] if s["rva"] == self.bss_rva), None)
            if (selected is None or selected["index"] >= _original_section_limit(pe["sections"])
                    or selected["raw_size"] != 0):
                raise ValueError("bss_rva must identify an original section with zero packed RawSize")
            return self.bss_rva, "explicit"
        limit = _original_section_limit(pe["sections"])
        options = [s["rva"] for s in pe["sections"][:limit]
                   if s["raw_size"] == 0 and s["characteristics"] & 0x80]
        if len(options) == 1:
            return options[0], "single_uninitialized_section"
        return None, "ambiguous_or_not_present"

    def set_bss_rva(self, rva: int | None) -> None:
        """Select a zero-raw-data original section before saving, or clear it."""
        _, pe, oep_rva = self._require_confirmed_oep()
        if self.phase not in ("at_oep", "await_save_path"):
            raise RuntimeError("set .bss only before the pre-Scylla dump is saved")
        if rva is not None:
            if not isinstance(rva, int) or rva < 0:
                raise ValueError(".bss section RVA must be a nonnegative integer")
            chosen = next((s for s in pe["sections"] if s["rva"] == rva), None)
            if chosen is None or chosen["index"] >= _original_section_limit(pe["sections"]):
                raise ValueError(".bss RVA must be an original section start")
            if chosen["raw_size"] != 0:
                raise ValueError("the selected section has nonzero packed RawSize")
            if chosen["rva"] <= oep_rva < chosen["rva"] + max(chosen["virtual_size"], chosen["raw_size"]):
                raise ValueError("OEP lies inside the selected .bss section")
        self.bss_rva = rva
        self._log(".bss selection", rva=f"0x{rva:X}" if rva is not None else "automatic")

    def _capture_and_save(self, path: Path) -> None:
        base, pe, oep_rva = self._require_confirmed_oep()
        outputs = self._output_paths(path)
        for item in outputs:
            if item.exists() or item.is_symlink():
                raise FileExistsError(f"output appeared after selection: {item}")
        image, unreadable = _capture_image(base, pe["size_of_image"])
        app_end_index = _original_section_limit(pe["sections"])
        app_end_rva = pe["sections"][app_end_index]["rva"]
        critical_holes = [hole for hole in unreadable if hole["rva"] < app_end_rva]
        if critical_holes:
            raise RuntimeError(f"{len(critical_holes)} original application/header pages are unreadable")
        if image[oep_rva : oep_rva + 16] != api.read_exact(self.oep, 16):
            raise RuntimeError("OEP bytes changed during image capture")
        bss_rva, bss_source = self._select_bss_rva(pe)
        prepared, conversion = core.prepare_mapped_pe(
            image, oep_rva, bss_rva=bss_rva, module_base=base,
        )
        try:
            iat = core.infer_iat(image, pe["sections"], base, _loaded_module_ranges())
        except ValueError as exc:
            iat = None
            self._log("IAT inference unavailable", error=str(exc))
        for item in outputs:
            if item.exists() or item.is_symlink():
                raise FileExistsError(f"output appeared during capture: {item}")
        report = {
            "format": "enigma740-generic-ida-pre-scylla-v1",
            "status": "pre_scylla_ready" if not unreadable else "pre_scylla_with_packer_holes",
            "scope": "Enigma x64 7.40 final transfer",
            "oep_source": self.oep_source,
            "protected_file": str(self.input_path),
            "protected_sha256": hashlib.sha256(self.disk_blob).hexdigest(),
            "module_name": self.module_name,
            "module_base": f"0x{base:X}",
            "packed_entry_rva": f"0x{pe['entry_rva']:X}",
            "final_jump_rva": f"0x{self.jump['rva']:X}",
            "oep_rva": f"0x{oep_rva:X}",
            "oep_va": f"0x{self.oep:X}",
            "oep_first_16_bytes": image[oep_rva : oep_rva + 16].hex(),
            "memory_file": str(outputs[1]),
            "memory_sha256": hashlib.sha256(image).hexdigest(),
            "pre_scylla_file": str(outputs[0]),
            "pre_scylla_sha256": hashlib.sha256(prepared).hexdigest(),
            "unreadable_pages": unreadable,
            "bss_source": bss_source,
            "iat": iat,
            "iat_confidence": iat["confidence"] if iat else None,
            "conversion": conversion,
            "events": self.events,
            "imports_rebuilt": False,
            "warning": "Scylla must rebuild imports. The prepared PE may require further metadata repair before cold launch.",
        }
        created: list[Path] = []
        try:
            with outputs[0].open("xb") as stream:
                created.append(outputs[0])
                stream.write(prepared)
            with outputs[1].open("xb") as stream:
                created.append(outputs[1])
                stream.write(image)
            with outputs[2].open("x", encoding="utf-8") as stream:
                created.append(outputs[2])
                json.dump(report, stream, indent=2, ensure_ascii=False)
                stream.write("\n")
        except Exception:
            for item in reversed(created):
                item.unlink(missing_ok=True)
            raise
        # Keep both API interception breakpoints and this hook alive. Enigma's
        # optional runtime anti-debug check may execute after the OEP.
        self.phase = "monitoring_runtime"
        self._log("pre-Scylla PE saved", path=str(outputs[0]))
        self._log("mapped memory saved", path=str(outputs[1]))
        self._log("capture report saved", path=str(outputs[2]))
        if iat and iat["confidence"] == "high":
            self._log("SCYLLA (hex)", OEP=f"{self.oep:016X}",
                      VA=f"{iat['va']:016X}", Size=f"{iat['size']:X}")
        else:
            self._log("SCYLLA OEP (hex)", OEP=f"{self.oep:016X}")
            self._log("IAT not confirmed; use Scylla IAT Autosearch", confidence=iat["confidence"] if iat else "none")
        self._log("runtime API monitoring remains active; call abort() to remove owned HBPs")

    def _prompt_and_save(self) -> bool:
        self.save_prompt_queued = False
        if self.phase != "await_save_path":
            return False
        try:
            self._require_confirmed_oep()
            path = self._choose_path()
            if path is None:
                self.phase = "at_oep"
                self._log("save cancelled; call enigma740_generic.save() to choose again")
                return False
            self._capture_and_save(path)
        except (ValueError, FileExistsError) as exc:
            self.phase = "at_oep"
            self._log("save path rejected", error=str(exc))
            ida_kernwin.warning(str(exc))
        except Exception as exc:
            self.failure = str(exc)
            self.phase = "at_oep"
            self._log("capture failed; process remains at OEP", error=str(exc))
        return False

    def _queue_save_prompt(self) -> None:
        self._require_confirmed_oep()
        if self.save_prompt_queued:
            return
        self.phase = "await_save_path"
        self.save_prompt_queued = True
        if not ida_kernwin.execute_ui_requests([self._prompt_and_save]):
            self.phase = "at_oep"
            self.save_prompt_queued = False
            raise RuntimeError("IDA could not schedule Save As dialog")
        self._log("OEP reached; Save As dialog queued")

    def save(self) -> None:
        """Open Save As again while still paused at the confirmed OEP."""
        self._queue_save_prompt()


def start(auto: bool = AUTO_CONTINUE, bss_rva: int | None = BSS_RVA) -> Workflow:
    print("[Enigma 7.40 generic] start requested")
    existing = getattr(builtins, "enigma740_generic", None)
    if (getattr(existing, "_enigma_workflow_token", None) == Workflow._enigma_workflow_token
            and existing.phase not in ("done", "aborted", "exited", "failed")):
        existing.status()
        return existing
    workflow = Workflow(auto=auto, bss_rva=bss_rva)
    builtins.enigma740_generic = workflow
    try:
        return workflow.start()
    except Exception:
        builtins.enigma740_generic = None
        raise


if __name__ == "__main__":
    try:
        start()
    except Exception as exc:
        print("[Enigma 7.40 generic] START FAILED: " + str(exc))
        ida_kernwin.warning("Enigma 7.40: o fluxo nao iniciou.\n" + str(exc))
        raise
