// IDC version of ida_find_themida_refs.py, for IDA installs without IDAPython.
//
// Lists where the code section of a dump made with Unlicense still transfers
// control to (or references) code outside of it, i.e. into Themida/WinLicense
// sections. This shows which parts of the original code are virtualized or
// mutated by Themida and still need manual analysis.
//
// Usage: open the dump (e.g. `unpacked_target.dll`) in IDA, wait for the
// auto-analysis to finish, then run this script (File > Script file...).
//
// Results are printed in the Output window and saved as a CSV file next to the
// IDB. Supports IDA 7.0 and later (32-bit and 64-bit).
//
// Note: this only locates references; it doesn't devirtualize anything.

#include <idc.idc>

// Returns the start of the segment holding the original code: the one named
// `.text` by Unlicense, or the one containing the entry point.
static find_code_segment()
{
  auto seg;
  for (seg = get_first_seg(); seg != BADADDR; seg = get_next_seg(seg)) {
    if (get_segm_name(seg) == ".text")
      return seg;
  }
  return get_segm_start(get_inf_attr(INF_START_EA));
}

static is_external_segment(ea)
{
  auto type;
  type = get_segm_attr(ea, SEGATTR_TYPE);
  return type == SEG_XTRN || type == SEG_IMP;
}

// Returns the address of the instruction following a `push imm` at `ea`, or
// BADADDR if there's no such instruction
static after_push_imm(ea)
{
  auto opcode;
  opcode = get_wide_byte(ea);
  if (opcode == 0x68)
    return ea + 5;
  if (opcode == 0x6A)
    return ea + 2;
  return BADADDR;
}

// Whether `target` looks like a VM entry stub (`push imm; jmp/call`)
static is_vm_stub(target)
{
  auto next, mnemonic;
  next = after_push_imm(target);
  if (next == BADADDR)
    return 0;
  mnemonic = print_insn_mnem(next);
  return mnemonic == "jmp" || mnemonic == "call";
}

static describe_stub(target)
{
  auto next;
  next = after_push_imm(target);
  if (next == BADADDR)
    return print_insn_mnem(target);
  return print_insn_mnem(target) + "; " + print_insn_mnem(next);
}

static is_function_start(ea)
{
  auto src;
  if (get_func_attr(ea, FUNCATTR_START) == ea)
    return 1;
  // Not (yet) a function for IDA, but called from somewhere
  for (src = get_first_fcref_to(ea); src != BADADDR;
       src = get_next_fcref_to(ea, src)) {
    if (print_insn_mnem(src) == "call")
      return 1;
  }
  return 0;
}

static classify(mnemonic, at_function_start, target_is_vm_stub)
{
  if (mnemonic == "jmp" && (at_function_start || target_is_vm_stub))
    return "vm-entry";
  if (substr(mnemonic, 0, 1) == "j")
    return "jmp-out";
  return "call-out";
}

static csv_quote(text)
{
  auto result, i, c;
  result = "";
  for (i = 0; i < strlen(text); i = i + 1) {
    c = substr(text, i, i + 1);
    if (c == "\"")
      result = result + "\"\"";
    else
      result = result + c;
  }
  return "\"" + result + "\"";
}

static csv_path()
{
  auto path, ext;
  path = get_idb_path();
  if (strlen(path) > 4) {
    ext = substr(path, strlen(path) - 4, -1);
    if (ext == ".idb" || ext == ".i64")
      path = substr(path, 0, strlen(path) - 4);
  }
  return path + "_themida_refs.csv";
}

static report(file, kind, ea, target, at_start)
{
  auto func_name, insn, seg_name, stub, start_text;
  func_name = get_func_name(ea);
  insn = generate_disasm_line(ea, 0);
  seg_name = get_segm_name(target);
  stub = describe_stub(target);
  msg("[%s] 0x%X %s: %s -> 0x%X (%s) [%s]\n", kind, ea, func_name, insn,
      target, seg_name, stub);
  start_text = "False";
  if (at_start)
    start_text = "True";
  fprintf(file, "%s,0x%X,%s,%s,%s,0x%X,%s,%s\n", kind, ea,
          csv_quote(func_name), start_text, csv_quote(insn), target,
          csv_quote(seg_name), csv_quote(stub));
}

static main()
{
  auto code_seg, code_end, path, file, pass, ea, mnemonic, target, target_seg;
  auto at_start, kind, code_target_segs, seg_key;
  auto count_vm, count_jmp, count_call, count_data;

  code_seg = find_code_segment();
  if (code_seg == BADADDR) {
    msg("Couldn't find the code segment (.text or entry point)\n");
    return;
  }
  code_end = get_segm_end(code_seg);
  path = csv_path();
  file = fopen(path, "w");
  if (file == 0) {
    msg("Couldn't create '%s'\n", path);
    return;
  }
  fprintf(file, "%s\n",
          "kind,source,function,function_start,instruction,target,target_segment,target_stub");

  msg("==============================================================\n");
  msg("Themida references from %s (0x%X-0x%X)\n", get_segm_name(code_seg),
      code_seg, code_end);
  msg("==============================================================\n");

  // Segments receiving code references from the code segment, as "|start|"
  code_target_segs = "|";
  count_vm = 0;
  count_jmp = 0;
  count_call = 0;
  count_data = 0;
  // Pass 0: code references, pass 1: data references to the segments found
  // in pass 0 (to leave out strings and other regular data)
  for (pass = 0; pass < 2; pass = pass + 1) {
    for (ea = code_seg; ea != BADADDR && ea < code_end;
         ea = next_head(ea, code_end)) {
      if (!is_code(get_full_flags(ea)))
        continue;
      mnemonic = print_insn_mnem(ea);
      if (pass == 0) {
        for (target = get_first_fcref_from(ea); target != BADADDR;
             target = get_next_fcref_from(ea, target)) {
          target_seg = get_segm_start(target);
          if (target_seg == BADADDR || target_seg == code_seg ||
              is_external_segment(target))
            continue;
          seg_key = sprintf("|%X|", target_seg);
          if (strstr(code_target_segs, seg_key) == -1)
            code_target_segs = code_target_segs + substr(seg_key, 1, -1);
          at_start = is_function_start(ea);
          kind = classify(mnemonic, at_start, is_vm_stub(target));
          if (kind == "vm-entry")
            count_vm = count_vm + 1;
          else if (kind == "jmp-out")
            count_jmp = count_jmp + 1;
          else
            count_call = count_call + 1;
          report(file, kind, ea, target, at_start);
        }
      } else {
        for (target = get_first_dref_from(ea); target != BADADDR;
             target = get_next_dref_from(ea, target)) {
          target_seg = get_segm_start(target);
          if (target_seg == BADADDR || target_seg == code_seg ||
              is_external_segment(target) ||
              is_data(get_full_flags(target)))
            continue;
          if (strstr(code_target_segs, sprintf("|%X|", target_seg)) == -1)
            continue;
          count_data = count_data + 1;
          report(file, "data-ref", ea, target, is_function_start(ea));
        }
      }
    }
  }
  fclose(file);

  msg("--------------------------------------------------------------\n");
  if (count_vm + count_jmp + count_call + count_data == 0) {
    msg("No references to code outside of the code segment found.\n");
    msg("The code segment doesn't seem to use Themida VM/mutation macros.\n");
    return;
  }
  msg("vm-entry  %4d  %s\n", count_vm,
      "jmp at a function start or to a 'push imm; jmp' stub: likely virtualized code");
  msg("jmp-out   %4d  %s\n", count_jmp,
      "jmp elsewhere: virtualized/mutated region or tail call");
  msg("call-out  %4d  %s\n", count_call,
      "call: mutated code, Themida SDK function or unresolved import wrapper");
  msg("data-ref  %4d  %s\n", count_data,
      "address of code outside the code segment (callback, function pointer...)");
  msg("CSV saved at '%s'\n", path);
}
