"""Conservative, debugger-independent helpers for Enigma x64 memory images.

The input to ``find_final_jump``, ``infer_iat`` and ``prepare_mapped_pe`` is a
*mapped* image read from a suspended process: file offset equals module RVA.
The packed executable on disk is sufficient only for ``parse_pe``. These
helpers deliberately refuse to invent an OEP, IAT span, or .bss section when
the observed bytes do not support one. They do not rebuild imports.
"""

from __future__ import annotations

import struct
from collections import Counter, defaultdict


FINAL_TRANSFER = bytes.fromhex("48 8B 45 E0 48 8B 65 F8 FF E0")
MAX_IMAGE_SIZE = 0x40000000
_IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x80
_IMAGE_SCN_CNT_CODE = 0x20
_IMAGE_SCN_CNT_INITIALIZED_DATA = 0x40
_IMAGE_SCN_MEM_EXECUTE = 0x20000000


def _u16(data: bytes, at: int) -> int:
    return struct.unpack_from("<H", data, at)[0]


def _u32(data: bytes, at: int) -> int:
    return struct.unpack_from("<I", data, at)[0]


def _u64(data: bytes, at: int) -> int:
    return struct.unpack_from("<Q", data, at)[0]


def _align(value: int, unit: int) -> int:
    return (value + unit - 1) // unit * unit


def parse_pe(data: bytes) -> dict:
    """Parse PE32+ headers from either a disk PE or a mapped memory image.

    All offsets in the returned ``sections`` refer to the *input headers*.
    This function checks structure and virtual bounds, but does not infer that
    the section table still describes the restored application accurately.
    """
    if len(data) < 0x100 or data[:2] != b"MZ":
        raise ValueError("missing DOS header")
    nt = _u32(data, 0x3C)
    if nt < 0x40 or nt > 0x100000 or nt + 24 > len(data):
        raise ValueError("invalid PE header offset")
    if data[nt : nt + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    coff = nt + 4
    machine = _u16(data, coff)
    count = _u16(data, coff + 2)
    opt_size = _u16(data, coff + 16)
    opt = coff + 20
    if machine != 0x8664 or opt_size < 0x70 or opt + opt_size > len(data):
        raise ValueError("expected an x64 PE32+ optional header")
    if _u16(data, opt) != 0x20B:
        raise ValueError("expected PE32+ optional header")
    if count < 1 or count > 96:
        raise ValueError("implausible section count")

    image_base = _u64(data, opt + 24)
    entry_rva = _u32(data, opt + 16)
    section_alignment = _u32(data, opt + 32)
    file_alignment = _u32(data, opt + 36)
    size_of_image = _u32(data, opt + 56)
    size_of_headers = _u32(data, opt + 60)
    if not (0x1000 <= size_of_image <= MAX_IMAGE_SIZE):
        raise ValueError("implausible SizeOfImage")
    if entry_rva >= size_of_image:
        raise ValueError("entry point outside image")
    if section_alignment < 0x200 or section_alignment & (section_alignment - 1):
        raise ValueError("invalid SectionAlignment")
    if file_alignment < 0x200 or file_alignment & (file_alignment - 1):
        raise ValueError("invalid FileAlignment")
    if section_alignment < file_alignment:
        raise ValueError("SectionAlignment is smaller than FileAlignment")

    table = opt + opt_size
    if table + count * 40 > len(data):
        raise ValueError("truncated section table")
    if size_of_headers < table + count * 40 or size_of_headers > size_of_image:
        raise ValueError("invalid SizeOfHeaders")
    sections = []
    previous_end = _align(size_of_headers, section_alignment)
    for index in range(count):
        header_offset = table + 40 * index
        name_bytes = data[header_offset : header_offset + 8].split(b"\0", 1)[0]
        name = name_bytes.decode("ascii", "replace")
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, header_offset + 8
        )
        characteristics = _u32(data, header_offset + 36)
        virtual_extent = max(virtual_size, raw_size)
        if rva < previous_end or rva >= size_of_image:
            raise ValueError(f"section {index} has invalid or overlapping RVA")
        if rva % section_alignment:
            raise ValueError(f"section {index} is not section aligned")
        if virtual_extent == 0 or rva + virtual_extent > size_of_image:
            raise ValueError(f"section {index} lies outside image")
        previous_end = _align(rva + virtual_extent, section_alignment)
        sections.append(
            {
                "index": index,
                "name": name,
                "rva": rva,
                "virtual_size": virtual_size,
                "raw_size": raw_size,
                "raw_offset": raw_offset,
                "characteristics": characteristics,
                "header_offset": header_offset,
            }
        )
    return {
        "image_base": image_base,
        "size_of_image": size_of_image,
        "entry_rva": entry_rva,
        "packed_entry_rva": entry_rva,
        "size_of_headers": size_of_headers,
        "section_alignment": section_alignment,
        "file_alignment": file_alignment,
        "nt_offset": nt,
        "optional_offset": opt,
        "sections": sections,
    }


def _mapped_pe(image: bytes) -> dict:
    pe = parse_pe(image)
    if len(image) < pe["size_of_image"]:
        raise ValueError(
            f"expected mapped image of at least 0x{pe['size_of_image']:X} bytes; "
            f"received 0x{len(image):X}"
        )
    return pe


def _appended_sections(pe: dict, sections: list[dict]) -> tuple[list[dict], str]:
    """Identify the observed two-section Enigma tail, with a resource anchor.

    When .rsrc survives, only later sections are possible packer sections.
    Without that anchor, the tail is a constrained heuristic: the packed entry
    must lie in the last section and at least one earlier section must exist.
    """
    if len(sections) < 2:
        raise ValueError("cannot establish appended packer sections")
    entry = pe["entry_rva"]
    last = sections[-1]
    if not last["rva"] <= entry < last["rva"] + max(last["virtual_size"], last["raw_size"]):
        raise ValueError("packed entry point is not in the final section")
    resources = [s["index"] for s in sections if s["name"].casefold() == ".rsrc"]
    if resources:
        anchor = max(resources)
        if anchor >= len(sections) - 2:
            raise ValueError("no separate appended packer section after .rsrc")
        return sections[anchor + 1 :], "after_resource_section"
    if len(sections) < 3:
        raise ValueError("cannot identify appended packer tail without .rsrc")
    return sections[-2:], "last_two_sections_without_resource_anchor"


def find_final_jump(image: bytes, sections: list[dict]) -> dict:
    """Find the one observed Enigma transfer ``mov; mov; jmp rax``.

    Returns its jump RVA and the matching signature evidence. A static packed
    file normally has not decrypted this sequence yet and will be rejected.
    """
    pe = _mapped_pe(image)
    if len(sections) != len(pe["sections"]) or any(
        a["rva"] != b["rva"] for a, b in zip(sections, pe["sections"])
    ):
        raise ValueError("sections do not match mapped PE headers")
    appended, anchor = _appended_sections(pe, sections)
    hits = []
    for section in appended:
        start = section["rva"]
        end = min(pe["size_of_image"], start + max(section["virtual_size"], section["raw_size"]))
        offset = start
        while True:
            offset = image.find(FINAL_TRANSFER, offset, end)
            if offset < 0:
                break
            hits.append({"signature_rva": offset, "rva": offset + 8, "section_index": section["index"]})
            offset += 1
    if len(hits) != 1:
        raise ValueError(
            f"expected one live final-jump signature in appended Enigma sections, found {len(hits)}"
        )
    return {"rva": hits[0]["rva"], "hits": hits, "section_anchor": anchor}


def infer_iat(
    image: bytes,
    sections: list[dict],
    module_base: int,
    loaded_dll_ranges: list[tuple[int, int, str]],
) -> dict | None:
    """Infer a single import table from restored ``FF 25`` thunks.

    Ranges are ``(base, size, DLL name)`` for DLLs loaded in this *same*
    debuggee. A pointer into an appended Enigma section is counted as a
    redirected import, but this helper cannot derive its actual API name.
    ``None`` means no uniquely supported interval; use Scylla's own search.
    """
    pe = _mapped_pe(image)
    if len(sections) != len(pe["sections"]) or any(
        a["rva"] != b["rva"] for a, b in zip(sections, pe["sections"])
    ):
        raise ValueError("sections do not match mapped PE headers")
    if module_base <= 0:
        raise ValueError("module_base must be the live module base")
    ranges = []
    for base, size, name in loaded_dll_ranges:
        if base < 0 or size <= 0 or not name:
            raise ValueError("invalid loaded DLL range")
        if base < module_base + pe["size_of_image"] and module_base < base + size:
            continue  # Never count the protected module itself as a DLL.
        ranges.append((base, base + size, name))
    if not ranges:
        return None
    def dll_for(value: int) -> str | None:
        for low, high, name in ranges:
            if low <= value < high:
                return name
        return None

    appended, _ = _appended_sections(pe, sections)
    app_limit = appended[0]["index"]
    if app_limit == 0:
        return None
    app_sections = sections[:app_limit]

    def app_section_at(rva: int) -> dict | None:
        for sec in app_sections:
            if sec["rva"] <= rva < sec["rva"] + max(sec["virtual_size"], sec["raw_size"]):
                return sec
        return None

    def target_kind(value: int) -> tuple[str, str] | None:
        dll = dll_for(value)
        if dll:
            return ("dll", dll)
        if module_base <= value < module_base + pe["size_of_image"]:
            target_rva = value - module_base
            for sec in appended:
                if sec["rva"] <= target_rva < sec["rva"] + max(sec["virtual_size"], sec["raw_size"]):
                    return ("enigma_redirect", f"section_{sec['index']}")
        return None

    refs: dict[int, list[int]] = defaultdict(list)
    syntactic_refs: dict[int, list[int]] = defaultdict(list)
    for sec in app_sections:
        start = sec["rva"]
        end = min(pe["size_of_image"], start + max(sec["virtual_size"], sec["raw_size"]))
        offset = start
        while True:
            offset = image.find(b"\xFF\x25", offset, end)
            if offset < 0:
                break
            if offset + 6 <= end:
                disp = struct.unpack_from("<i", image, offset + 2)[0]
                slot = offset + 6 + disp
                if 0 <= slot <= pe["size_of_image"] - 8 and app_section_at(slot):
                    syntactic_refs[slot].append(offset)
                    target = _u64(image, slot)
                    if target_kind(target):
                        refs[slot].append(offset)
            offset += 1
    if len(refs) < 4:
        return None

    # Group by the section containing the qword slots and by a shared qword
    # phase. A PE IAT can begin at RVA % 8 == 4, as in the first test sample.
    buckets: dict[tuple[int, int], list[int]] = defaultdict(list)
    for slot in refs:
        section = app_section_at(slot)
        assert section is not None
        buckets[(section["index"], slot % 8)].append(slot)

    candidates = []
    for (section_index, _phase), slots in buckets.items():
        slots.sort()
        groups: list[list[int]] = [[slots[0]]]
        for slot in slots[1:]:
            if slot - groups[-1][-1] <= 0x200:
                groups[-1].append(slot)
            else:
                groups.append([slot])
        section = sections[section_index]
        high = min(pe["size_of_image"], section["rva"] + max(section["virtual_size"], section["raw_size"]))
        for group in groups:
            if len(group) < 4:
                continue
            begin = group[0]
            # Scan backward through adjacent import pointers. Never include
            # leading zero padding because it has no thunk evidence.
            while begin - 8 >= section["rva"] and target_kind(_u64(image, begin - 8)):
                begin -= 8
            end = group[-1] + 8
            if end + 8 > high or _u64(image, end) != 0:
                continue  # No terminator: cannot determine the exact Size.
            end += 8  # Exactly one final null qword, not arbitrary padding.
            values = [_u64(image, offset) for offset in range(begin, end, 8)]
            if any(value and not target_kind(value) for value in values):
                continue
            linked = {slot: refs[slot] for slot in group if begin <= slot < end}
            kinds = [target_kind(value) for value in values if value]
            direct = sum(kind[0] == "dll" for kind in kinds if kind)
            redirected = sum(kind[0] == "enigma_redirect" for kind in kinds if kind)
            # Internal Enigma pointers alone cannot establish an import table.
            if direct < 2 or direct + redirected < 4:
                continue
            candidates.append((begin, end, linked, values, direct, redirected))
    if len(candidates) != 1:
        return None  # Multiple credible tables or no table: let Scylla search.

    begin, end, linked, values, direct, redirected = candidates[0]
    refs_count = len(linked)
    if refs_count < 4:
        return None
    selected_section = app_section_at(begin)
    assert selected_section is not None
    same_table_phase = {
        slot: places for slot, places in syntactic_refs.items()
        if app_section_at(slot) is selected_section and slot % 8 == begin % 8
    }
    # A partial live IAT can leave earlier thunks referencing zero/unresolved
    # qwords. A smaller tail can otherwise look like a valid, complete table.
    if any(begin <= slot < end and _u64(image, slot) == 0 for slot in same_table_phase):
        return None
    unexplained_slots = [slot for slot in same_table_phase if not begin <= slot < end]
    if len(unexplained_slots) >= 4:
        return None
    groups = []
    count = 0
    for value in values:
        if value:
            count += 1
        else:
            if count:
                groups.append(count)
            count = 0
    dlls = Counter(dll_for(value) for value in values if value and dll_for(value))
    redirect_sections = Counter(
        target_kind(value)[1] for value in values
        if value and target_kind(value) and target_kind(value)[0] == "enigma_redirect"
    )
    return {
        "rva": begin,
        "va": module_base + begin,
        "size": end - begin,
        # Confidence describes the *VA/Size interval*, not API-name recovery.
        "confidence": (
            "high" if refs_count >= 8 and refs_count == direct + redirected and not unexplained_slots
            else "candidate"
        ),
        "evidence": {
            "ff25_thunks": sum(len(places) for places in linked.values()),
            "referenced_slots": refs_count,
            "nonzero_entries": len([v for v in values if v]),
            "zero_terminators": values.count(0),
            "group_counts": groups,
            "target_dlls": dict(dlls),
            "direct_entries": direct,
            "redirected_entries": redirected,
            "redirect_sections": dict(redirect_sections),
            "direct_exports_only": redirected == 0,
            "unexplained_same_section_thunks": len(unexplained_slots),
            "warning": "DLL-range membership does not resolve API aliases; Enigma redirects require Scylla tracing",
        },
    }


def prepare_mapped_pe(
    image: bytes,
    oep_rva: int,
    bss_rva: int | None = None,
    module_base: int | None = None,
) -> tuple[bytes, dict]:
    """Make a mapped OEP image parseable as a PE with mapped raw offsets.

    Every materialized section gets ``PointerToRawData == VirtualAddress``.
    Only an explicitly selected uninitialized section is given zero raw size;
    its live bytes remain in the separate raw memory image supplied by caller.
    This is a pre-Scylla intermediate, not a standalone unpacked executable.
    """
    pe = _mapped_pe(image)
    if module_base is not None and (module_base <= 0 or module_base & 0xFFFF):
        raise ValueError("module_base must be the live, 64 KiB-aligned image base")
    if not (0 < oep_rva < pe["size_of_image"]):
        raise ValueError("OEP RVA outside mapped image")
    if not any(s["rva"] <= oep_rva < s["rva"] + max(s["virtual_size"], s["raw_size"]) for s in pe["sections"]):
        raise ValueError("OEP RVA is not inside a section")
    selected = None
    if bss_rva is not None:
        selected = next((s for s in pe["sections"] if s["rva"] == bss_rva), None)
        if selected is None:
            raise ValueError("bss_rva is not a section start")
        if selected["rva"] <= oep_rva < selected["rva"] + max(selected["virtual_size"], selected["raw_size"]):
            raise ValueError("OEP cannot lie inside the selected .bss section")

    output = bytearray(image)
    section_report = []
    intervals = []
    for sec in pe["sections"]:
        start = sec["rva"]
        next_start = pe["sections"][sec["index"] + 1]["rva"] if sec["index"] + 1 < len(pe["sections"]) else pe["size_of_image"]
        virtual_extent = max(sec["virtual_size"], sec["raw_size"])
        raw_size = _align(virtual_extent, pe["file_alignment"])
        if start + raw_size > next_start or start + raw_size > pe["size_of_image"]:
            raise ValueError(f"section {sec['index']} raw layout would overlap the next section")
        header = sec["header_offset"]
        is_bss = sec is selected
        if is_bss:
            # The caller explicitly classified this section. The PE loader
            # must create zero-filled storage, so live process bytes are not
            # copied into the *prepared PE*. The raw memory image is untouched.
            output[start : start + raw_size] = b"\0" * raw_size
            struct.pack_into("<II", output, header + 16, 0, 0)
            uninitialized_flags = (
                sec["characteristics"]
                & ~(_IMAGE_SCN_CNT_CODE | _IMAGE_SCN_CNT_INITIALIZED_DATA | _IMAGE_SCN_MEM_EXECUTE)
            ) | _IMAGE_SCN_CNT_UNINITIALIZED_DATA
            struct.pack_into("<I", output, header + 36, uninitialized_flags)
        else:
            struct.pack_into("<II", output, header + 16, raw_size, start)
            intervals.append((start, start + raw_size, sec["index"]))
        section_report.append(
            {
                "index": sec["index"],
                "rva": start,
                "virtual_size": sec["virtual_size"],
                "old_raw_size": sec["raw_size"],
                "new_raw_size": 0 if is_bss else raw_size,
                "new_raw_offset": 0 if is_bss else start,
                "bss_selected": is_bss,
            }
        )
    intervals.sort()
    for left, right in zip(intervals, intervals[1:]):
        if left[1] > right[0]:
            raise ValueError("prepared raw sections overlap")

    opt = pe["optional_offset"]
    struct.pack_into("<I", output, opt + 16, oep_rva)
    if module_base is not None:
        # The captured code and data have already received loader relocations.
        # Record that same base so a later load computes its delta from the
        # captured state, not from the packed file's original preferred base.
        struct.pack_into("<Q", output, opt + 24, module_base)
    header_end = pe["sections"][-1]["header_offset"] + 40
    headers = _align(header_end, pe["file_alignment"])
    if headers > pe["sections"][0]["rva"]:
        raise ValueError("PE headers overlap the first section")
    struct.pack_into("<I", output, opt + 60, headers)
    struct.pack_into("<I", output, opt + 64, 0)  # Checksum belongs to the new file.
    # The security directory uses a disk offset, not an RVA. The mapped
    # snapshot does not contain a trustworthy Authenticode overlay.
    if _u32(output, opt + 108) >= 5 and opt + 112 + 8 * 5 <= opt + (_u16(output, pe["nt_offset"] + 4 + 16)):
        struct.pack_into("<II", output, opt + 112 + 8 * 4, 0, 0)

    prepared = bytes(output)
    parsed = parse_pe(prepared)
    if parsed["entry_rva"] != oep_rva:
        raise ValueError("prepared OEP verification failed")
    return prepared, {
        "input_layout": "mapped_image",
        "output_stage": "pre_scylla",
        "oep_rva": oep_rva,
        "image_base_in_header": pe["image_base"],
        "capture_module_base": module_base,
        "output_image_base": module_base if module_base is not None else pe["image_base"],
        "aslr_rebased_header": module_base is not None and module_base != pe["image_base"],
        "size_of_image": pe["size_of_image"],
        "bss_rva": bss_rva,
        "bss_was_explicit": bss_rva is not None,
        "sections": section_report,
        "iat_rebuilt": False,
        "cold_launch_guaranteed": False,
        "warning": (
            "Scylla must rebuild imports; packed metadata and runtime data can still require repair. "
            "If the image was relocated, pass its live module_base to avoid an inconsistent PE header."
        ),
    }
