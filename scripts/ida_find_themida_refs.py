"""
IDAPython script listing where the code section of a dump made with Unlicense
still transfers control to (or references) code outside of it, i.e. into
Themida/WinLicense sections. This shows which parts of the original code are
virtualized or mutated by Themida and still need manual analysis.

Usage: open the dump (e.g. `unpacked_target.dll`) in IDA, wait for the
auto-analysis to finish, then run this script (File > Script file...).

Results are printed in the Output window and saved as a CSV file next to the
IDB. Supports IDA 7.4 and later (32-bit and 64-bit).

Note: this only locates references; it doesn't devirtualize anything.
"""
import csv
import os
from collections import defaultdict

import ida_bytes
import ida_funcs
import ida_ida
import ida_nalt
import ida_segment
import ida_ua
import idautils
import idc

# Add an IDA comment on each referencing instruction
ANNOTATE = False
# Number of instructions decoded at a target to recognize VM entry stubs
STUB_PEEK_COUNT = 3

KIND_VM_ENTRY = "vm-entry"
KIND_JMP_OUT = "jmp-out"
KIND_CALL_OUT = "call-out"
KIND_DATA_REF = "data-ref"


def find_code_segment():
    """
    Returns the segment holding the original code: the one named `.text` by
    Unlicense, or the one containing the entry point.
    """
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if ida_segment.get_segm_name(seg) == ".text":
            return seg
    return ida_segment.getseg(ida_ida.inf_get_start_ea())


def is_external_segment(seg):
    return seg.type in (ida_segment.SEG_XTRN, ida_segment.SEG_IMP)


def decode(ea):
    """Decodes the instruction at `ea`, even if it isn't defined as code."""
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) <= 0:
        return None
    return insn


def describe_stub(target):
    """
    Returns a short description of the first instructions at `target` and
    whether they look like a VM entry stub (`push imm; jmp/call`).
    """
    mnemonics = []
    ea = target
    for _ in range(STUB_PEEK_COUNT):
        insn = decode(ea)
        if insn is None:
            break
        mnemonics.append(insn.get_canon_mnem())
        if mnemonics[-1] in ("jmp", "ret", "retn"):
            break
        ea += insn.size
    is_vm_stub = (len(mnemonics) >= 2 and mnemonics[0] == "push"
                  and mnemonics[1] in ("jmp", "call"))
    if is_vm_stub:
        first = decode(target)
        is_vm_stub = first is not None and first.ops[0].type == ida_ua.o_imm
    return "; ".join(mnemonics), is_vm_stub


def is_function_start(ea):
    func = ida_funcs.get_func(ea)
    if func is not None and func.start_ea == ea:
        return True
    # Not (yet) a function for IDA, but called from somewhere
    for src in idautils.CodeRefsTo(ea, 0):
        if idc.print_insn_mnem(src) == "call":
            return True
    return False


def classify(mnemonic, at_function_start, target_is_vm_stub):
    if mnemonic == "jmp" and (at_function_start or target_is_vm_stub):
        return KIND_VM_ENTRY
    if mnemonic.startswith("j"):
        return KIND_JMP_OUT
    return KIND_CALL_OUT


def collect_refs(code_seg):
    """
    Returns a list of dicts describing every reference from the code segment
    to code outside of it.
    """
    code_refs = []
    data_refs = []
    code_target_segs = set()
    for ea in idautils.Heads(code_seg.start_ea, code_seg.end_ea):
        if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
            continue
        mnemonic = idc.print_insn_mnem(ea)
        for target in idautils.CodeRefsFrom(ea, 0):
            target_seg = ida_segment.getseg(target)
            if target_seg is None or target_seg.start_ea == code_seg.start_ea \
                    or is_external_segment(target_seg):
                continue
            code_target_segs.add(target_seg.start_ea)
            code_refs.append((ea, mnemonic, target, target_seg))
        for target in idautils.DataRefsFrom(ea):
            target_seg = ida_segment.getseg(target)
            if target_seg is None or target_seg.start_ea == code_seg.start_ea \
                    or is_external_segment(target_seg):
                continue
            data_refs.append((ea, mnemonic, target, target_seg))

    refs = []
    for ea, mnemonic, target, target_seg in code_refs:
        stub, is_vm_stub = describe_stub(target)
        at_start = is_function_start(ea)
        refs.append(
            make_ref(ea, mnemonic, target, target_seg, stub,
                     classify(mnemonic, at_start, is_vm_stub), at_start))
    # Only keep data references to segments that also receive code references
    # from the code segment, and to addresses not defined as data (e.g. IAT
    # entries or strings)
    for ea, mnemonic, target, target_seg in data_refs:
        if target_seg.start_ea not in code_target_segs or \
                ida_bytes.is_data(ida_bytes.get_flags(target)):
            continue
        stub, _ = describe_stub(target)
        refs.append(
            make_ref(ea, mnemonic, target, target_seg, stub, KIND_DATA_REF,
                     is_function_start(ea)))
    return refs


def make_ref(ea, mnemonic, target, target_seg, stub, kind, at_start):
    func_name = ida_funcs.get_func_name(ea) or ""
    return {
        "kind": kind,
        "source": ea,
        "function": func_name,
        "function_start": at_start,
        "instruction": idc.generate_disasm_line(ea, 0) or mnemonic,
        "target": target,
        "target_segment": ida_segment.get_segm_name(target_seg) or "",
        "target_stub": stub,
    }


def print_report(code_seg, refs):
    print("=" * 78)
    print("Themida references from %s (0x%X-0x%X)" %
          (ida_segment.get_segm_name(code_seg), code_seg.start_ea,
           code_seg.end_ea))
    print("=" * 78)
    if len(refs) == 0:
        print("No references to code outside of the code segment found.")
        print("The code segment doesn't seem to use Themida VM/mutation "
              "macros.")
        return

    by_kind = defaultdict(list)
    for ref in refs:
        by_kind[ref["kind"]].append(ref)
    descriptions = [
        (KIND_VM_ENTRY, "jmp at a function start or to a 'push imm; jmp' "
         "stub: likely virtualized code"),
        (KIND_JMP_OUT, "jmp elsewhere: virtualized/mutated region or tail "
         "call"),
        (KIND_CALL_OUT, "call: mutated code, Themida SDK function or "
         "unresolved import wrapper"),
        (KIND_DATA_REF, "address of code outside the code segment (callback, "
         "function pointer...)"),
    ]
    for kind, description in descriptions:
        print("%-9s %4d  %s" % (kind, len(by_kind[kind]), description))

    functions = set(r["function"] or hex(r["source"]) for r in refs)
    targets = set(r["target"] for r in refs)
    segments = set(r["target_segment"] for r in refs)
    print("Functions involved: %d, distinct targets: %d, target segments: %s" %
          (len(functions), len(targets), ", ".join(sorted(segments))))
    print("-" * 78)
    for kind, _ in descriptions:
        for ref in sorted(by_kind[kind], key=lambda r: r["source"]):
            print("[%s] 0x%X %s: %s -> 0x%X (%s) [%s]" %
                  (kind, ref["source"], ref["function"]
                   or "?", ref["instruction"], ref["target"],
                   ref["target_segment"], ref["target_stub"]))


def save_csv(refs):
    idb_path = idc.get_idb_path()
    base = os.path.splitext(idb_path)[0] if idb_path else \
        ida_nalt.get_root_filename()
    csv_path = base + "_themida_refs.csv"
    fields = [
        "kind", "source", "function", "function_start", "instruction",
        "target", "target_segment", "target_stub"
    ]
    with open(csv_path, "w", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fields)
        writer.writeheader()
        for ref in sorted(refs, key=lambda r: r["source"]):
            row = dict(ref)
            row["source"] = "0x%X" % ref["source"]
            row["target"] = "0x%X" % ref["target"]
            writer.writerow(row)
    return csv_path


def annotate(refs):
    for ref in refs:
        idc.set_cmt(ref["source"],
                    "Themida %s -> 0x%X" % (ref["kind"], ref["target"]), 0)


def main():
    code_seg = find_code_segment()
    if code_seg is None:
        print("Couldn't find the code segment (.text or entry point)")
        return
    refs = collect_refs(code_seg)
    print_report(code_seg, refs)
    if len(refs) > 0:
        print("-" * 78)
        print("CSV saved at '%s'" % save_csv(refs))
        if ANNOTATE:
            annotate(refs)


if __name__ == "__main__":
    main()
