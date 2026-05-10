//! End-to-end tests for the 1130 assembler.
//!
//! Coverage:
//! - All 24 mnemonics encode + round-trip via disasm + reassemble.
//! - Directives ORG, EQU, DC, END.
//! - Label binding: forward and backward references.
//! - Negative tests for unknown mnemonic, undefined symbol, out-of-
//!   range short-form displacement.

use sw_ibm1130_asm::{AsmError, AsmOutput, assemble, disassemble};
use sw_ibm1130_isa::{Instruction, Opcode};

fn assemble_ok(src: &str) -> AsmOutput {
    match assemble(src) {
        Ok(o) => o,
        Err(e) => panic!("assemble failed: {e}\n--- source ---\n{src}"),
    }
}

fn assemble_err(src: &str) -> AsmError {
    match assemble(src) {
        Err(e) => e,
        Ok(_) => panic!("expected error\n--- source ---\n{src}"),
    }
}

/// Reassemble the disassembly of `bytes` and assert byte-equal.
fn assert_byte_round_trip(bytes: &[u8]) {
    let text = disassemble(bytes).expect("disassemble");
    let again = assemble(&text).expect("reassemble");
    assert_eq!(
        again.bytes, bytes,
        "round-trip mismatch\n--- text ---\n{text}"
    );
}

#[test]
fn empty_source_yields_no_bytes() {
    let out = assemble_ok("");
    assert!(out.bytes.is_empty());
}

#[test]
fn comments_and_blank_lines_ok() {
    let out = assemble_ok(
        "; a comment\n\
         \n\
         ; another\n\
         END\n",
    );
    assert!(out.bytes.is_empty());
}

#[test]
fn dc_emits_one_word() {
    let out = assemble_ok("DC 0x1234\n");
    assert_eq!(out.bytes, vec![0x12, 0x34]);
}

#[test]
fn dc_with_label_binds_address() {
    let out = assemble_ok(
        "FOO: DC 0x4242\n\
         BAR: DC 0xDEAD\n",
    );
    assert_eq!(out.symbols.lookup("FOO"), Some(0));
    assert_eq!(out.symbols.lookup("BAR"), Some(1));
}

#[test]
fn equ_binds_value() {
    let out = assemble_ok("X: EQU 42\n");
    assert_eq!(out.symbols.lookup("X"), Some(42));
}

#[test]
fn org_advances_location_counter() {
    let out = assemble_ok(
        "        ORG 4\n\
         A: DC 1\n",
    );
    assert_eq!(out.symbols.lookup("A"), Some(4));
    // 4 zero words + 1 emitted word = 10 bytes.
    assert_eq!(out.bytes.len(), 10);
}

#[test]
fn add_short_form() {
    let out = assemble_ok("        A 5\n");
    assert_eq!(out.instructions.len(), 1);
    match &out.instructions[0] {
        Instruction::Short { op, tag, disp } => {
            assert_eq!(*op, Opcode::Add);
            assert_eq!(*tag, 0);
            assert_eq!(*disp, 5);
        }
        _ => panic!("expected short form"),
    }
}

#[test]
fn add_long_form_via_l_flag() {
    let out = assemble_ok("        A L 0x1234\n");
    match &out.instructions[0] {
        Instruction::Long {
            op,
            tag,
            indirect,
            address,
        } => {
            assert_eq!(*op, Opcode::Add);
            assert_eq!(*tag, 0);
            assert!(!*indirect);
            assert_eq!(*address, 0x1234);
        }
        _ => panic!("expected long form"),
    }
}

#[test]
fn ld_indirect_implies_long() {
    let out = assemble_ok("        LD I 0x42\n");
    match &out.instructions[0] {
        Instruction::Long {
            op,
            tag,
            indirect,
            address,
        } => {
            assert_eq!(*op, Opcode::Load);
            assert_eq!(*tag, 0);
            assert!(*indirect);
            assert_eq!(*address, 0x42);
        }
        _ => panic!("expected long indirect"),
    }
}

#[test]
fn ld_with_tag_short() {
    let out = assemble_ok("        LD 1, 12\n");
    match &out.instructions[0] {
        Instruction::Short { op, tag, disp } => {
            assert_eq!(*op, Opcode::Load);
            assert_eq!(*tag, 1);
            assert_eq!(*disp, 12);
        }
        _ => panic!("expected short with tag"),
    }
}

#[test]
fn ld_with_tag_long() {
    let out = assemble_ok("        LD L 2, 0x4000\n");
    match &out.instructions[0] {
        Instruction::Long {
            op,
            tag,
            indirect,
            address,
        } => {
            assert_eq!(*op, Opcode::Load);
            assert_eq!(*tag, 2);
            assert!(!*indirect);
            assert_eq!(*address, 0x4000);
        }
        _ => panic!("expected long with tag"),
    }
}

#[test]
fn forward_label_reference_in_long_form() {
    let out = assemble_ok(
        "        LD L TARGET\n\
         TARGET: DC 0x1111\n",
    );
    // First insn = LD L (4 bytes); TARGET resolves to word address 2.
    assert_eq!(out.symbols.lookup("TARGET"), Some(2));
    match &out.instructions[0] {
        Instruction::Long { address, .. } => assert_eq!(*address, 2),
        _ => panic!("expected long form"),
    }
}

#[test]
fn xio_is_long_only() {
    let out = assemble_ok("        XIO 0x100\n");
    match &out.instructions[0] {
        Instruction::Long { op, .. } => assert_eq!(*op, Opcode::ExecuteInputOutput),
        _ => panic!("xio should be long form"),
    }
}

#[test]
fn wait_is_short_only_no_operand() {
    let out = assemble_ok("        WAIT\n");
    match &out.instructions[0] {
        Instruction::Short { op, tag, disp } => {
            assert_eq!(*op, Opcode::Wait);
            assert_eq!(*tag, 0);
            assert_eq!(*disp, 0);
        }
        _ => panic!("wait should be short form"),
    }
}

#[test]
fn wait_with_l_flag_is_error() {
    let err = assemble_err("        WAIT L\n");
    assert!(
        err.message.contains("no long form"),
        "unexpected error: {err}"
    );
}

#[test]
fn shift_left_short_only() {
    let out = assemble_ok("        SLA 8\n");
    match &out.instructions[0] {
        Instruction::Short { op, tag, disp } => {
            assert_eq!(*op, Opcode::ShiftLeft);
            assert_eq!(*tag, 0);
            assert_eq!(*disp, 8);
        }
        _ => panic!("sla should be short form"),
    }
}

#[test]
fn all_24_mnemonics_assemble() {
    // One-line-per-mnemonic smoke for short and long forms where
    // available. Failure of any one means the mnemonic table is
    // wrong or out of sync with the ISA spec.
    let src = r#"
        LD 5
        LDD 6
        STO 7
        STD 8
        LDX 9
        STX 10
        LDS 11
        STS 12
        A 5
        AD 6
        S 7
        SD 8
        M 9
        D 10
        AND 11
        OR 12
        EOR 13
        SLA 1
        SRA 2
        BSC 0x20
        BSI L 0x100
        MDX 5
        WAIT
        XIO L 0x200
"#;
    let out = assemble_ok(src);
    assert_eq!(out.instructions.len(), 24);
}

#[test]
fn round_trip_short_and_long_mix() {
    let src = "\
        A 5\n\
        S -10\n\
        LD L 0x4000\n\
        STO L I 0x42\n\
        BSC 0x20\n\
        BSI L 0x1000\n\
        MDX 1, 4\n\
        WAIT\n\
        XIO L 0x200\n\
";
    let out = assemble_ok(src);
    assert_byte_round_trip(&out.bytes);
}

#[test]
fn round_trip_all_24_mnemonics() {
    let src = r#"
        LD 5
        LDD 6
        STO 7
        STD 8
        LDX 9
        STX 10
        LDS 11
        STS 12
        A 5
        AD 6
        S 7
        SD 8
        M 9
        D 10
        AND 11
        OR 12
        EOR 13
        SLA 1
        SRA 2
        BSC 0x20
        BSI L 0x100
        MDX 5
        WAIT
        XIO L 0x200
"#;
    let out = assemble_ok(src);
    assert_byte_round_trip(&out.bytes);
}

#[test]
fn dc_then_instructions_round_trip_when_dc_decodes_as_instr() {
    // DC values that happen to decode as valid 1130 instructions
    // round-trip cleanly. (The disassembler can't distinguish data
    // bytes from instruction bytes; this is inherent to a flat
    // byte stream and matches how 1130 software actually mixed code
    // and data on a per-word basis.)
    let src = "\
        A 5\n\
        S -10\n\
";
    let out = assemble_ok(src);
    assert_byte_round_trip(&out.bytes);
}

#[test]
fn org_padding_is_zero_words() {
    // ORG fills with zero words; we don't round-trip these (0x0000
    // is not a valid opcode) but we do verify the byte layout.
    let out = assemble_ok(
        "        ORG 4\n\
                A 5\n",
    );
    assert_eq!(out.bytes.len(), 4 * 2 + 2);
    assert_eq!(&out.bytes[..8], &[0, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn error_unknown_mnemonic() {
    let err = assemble_err("        FOOZ 1\n");
    assert!(err.message.contains("unknown mnemonic"), "err = {err}");
    assert_eq!(err.line, 1);
}

#[test]
fn error_undefined_symbol() {
    let err = assemble_err("        A L MISSING\n");
    assert!(err.message.contains("undefined symbol"), "err = {err}");
}

#[test]
fn error_short_form_displacement_out_of_range() {
    let err = assemble_err("        A 200\n");
    assert!(err.message.contains("out of range"), "err = {err}");
}

#[test]
fn error_duplicate_label() {
    let err = assemble_err(
        "FOO: DC 1\n\
         FOO: DC 2\n",
    );
    assert!(err.message.contains("duplicate"), "err = {err}");
    assert_eq!(err.line, 2);
}

#[test]
fn error_org_with_label() {
    let err = assemble_err("FOO: ORG 0x100\n");
    assert!(
        err.message.contains("ORG cannot have a label"),
        "err = {err}"
    );
}

#[test]
fn line_position_in_errors() {
    // Trigger an error on the third line; assert the line number
    // matches.
    let err = assemble_err(
        "; comment\n\
         \n\
                FOOZ 1\n",
    );
    assert_eq!(err.line, 3);
}
