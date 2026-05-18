//! Pass 2: parsed lines + symbol table -> bytes.
//!
//! For each line, look up operand values, decide short vs long
//! form, build a `sw_ibm1130_isa::Instruction`, and call
//! `sw_ibm1130_isa::encode::encode` to get the bytes.

use sw_ibm1130_isa::{Instruction, Opcode, encode};

use crate::AsmError;
use crate::AsmOutput;
use crate::parser::{Directive, LineBody, Operand, ParsedLine};
use crate::symtab::{SymbolTable, instruction_size_words};

/// Drives pass 2.
pub fn emit_pass2(lines: &[ParsedLine], symbols: &SymbolTable) -> Result<AsmOutput, AsmError> {
    let mut bytes = Vec::new();
    let mut instructions = Vec::new();
    let mut lc: i64 = 0;

    for line in lines {
        match &line.body {
            LineBody::Empty => {}
            LineBody::Directive(d) => match d {
                Directive::Org(op) => {
                    let v = resolve(op, symbols, lc, line.line)?;
                    if v < lc {
                        return Err(AsmError::new(
                            line.line,
                            1,
                            "ORG cannot move location counter backward",
                        ));
                    }
                    // Pad with zero words to the new origin.
                    let pad_words = (v - lc) as usize;
                    bytes.extend(std::iter::repeat_n(0u8, pad_words * 2));
                    for _ in 0..pad_words {
                        instructions.push(Instruction::Long {
                            op: Opcode::Wait,
                            tag: 0,
                            indirect: false,
                            mask: 0,
                            address: 0,
                        });
                    }
                    lc = v;
                }
                Directive::Equ(_) => {
                    // Pass 1 handled the binding; nothing to emit.
                }
                Directive::Dc(op) => {
                    let v = resolve(op, symbols, lc, line.line)?;
                    let word = (v as i32 as u32 as u16).to_be_bytes();
                    bytes.extend_from_slice(&word);
                    instructions.push(Instruction::Long {
                        op: Opcode::Wait,
                        tag: 0,
                        indirect: false,
                        mask: 0,
                        address: v as u16,
                    });
                    lc += 1;
                }
                Directive::Bss(op) => {
                    let n = resolve(op, symbols, lc, line.line)?;
                    if n < 0 {
                        return Err(AsmError::new(
                            line.line,
                            1,
                            format!("BSS size must be non-negative; got {n}"),
                        ));
                    }
                    let n = n as usize;
                    bytes.extend(std::iter::repeat_n(0u8, n * 2));
                    for _ in 0..n {
                        instructions.push(Instruction::Long {
                            op: Opcode::Wait,
                            tag: 0,
                            indirect: false,
                            mask: 0,
                            address: 0,
                        });
                    }
                    lc += n as i64;
                }
                Directive::Abs => {
                    // ABS is a no-op: declares the program as non-
                    // relocatable. We don't relocate.
                }
                Directive::End(_entry) => break,
            },
            LineBody::Instruction(insn) => {
                let opcode = mnemonic_to_opcode(&insn.mnemonic, line.line, insn.mnemonic_col)?;
                let force_short = is_short_only(&insn.mnemonic);
                // Auto-promote to long form when the operand is a
                // symbol or expression (i.e. anything other than a
                // bare number). Numbers default to short (the user
                // can override with `L`); symbols typically resolve
                // out of short-form's 8-bit range, and the 1968 IBM
                // 1130 Assembler made this auto-promote silently
                // for symbolic operands. Replicate that behaviour
                // to keep historical source ingestible without
                // sprinkling `L` flags across hundreds of lines.
                let symbolic_operand = matches!(
                    &insn.operand,
                    Some(Operand::Symbol(_))
                        | Some(Operand::LocationCounter)
                        | Some(Operand::Offset { .. })
                        | Some(Operand::Multiply { .. })
                );
                let want_long = (insn.long_flag
                    || insn.indirect_flag
                    || is_long_only(&insn.mnemonic)
                    || symbolic_operand)
                    && !force_short;

                if force_short && (insn.long_flag || insn.indirect_flag) {
                    return Err(AsmError::new(
                        line.line,
                        insn.mnemonic_col,
                        format!("`{}` has no long form", insn.mnemonic),
                    ));
                }

                let built = if want_long {
                    build_long(insn, opcode, symbols, lc, line.line)?
                } else {
                    build_short(insn, opcode, symbols, lc, line.line)?
                };

                let mut buf = [0u8; 4];
                let n = encode::encode(&built, &mut buf).map_err(|e| {
                    AsmError::new(
                        line.line,
                        insn.mnemonic_col,
                        format!("encode failed: {e:?}"),
                    )
                })?;
                bytes.extend_from_slice(&buf[..n]);
                instructions.push(built);
                lc += instruction_size_words(insn);
            }
        }
    }

    Ok(AsmOutput {
        bytes,
        symbols: symbols.clone(),
        instructions,
    })
}

fn build_short(
    insn: &crate::parser::Instruction,
    op: Opcode,
    symbols: &SymbolTable,
    lc: i64,
    line: u32,
) -> Result<Instruction, AsmError> {
    let count_value = match &insn.operand {
        Some(o) => resolve(o, symbols, lc, line)?,
        None => 0,
    };
    // Shift sub-ops (SLT, SRT): OR the sub-op selector bits into
    // the high bits of the displacement byte. Per the IBM 1130 FC
    // manual: bit 8 of the instruction word (high bit of the disp
    // byte) = "shift-together" selector, meaning ACC+EXT shift as
    // a 32-bit pair.
    let disp_value = if let Some(sub_bits) = shift_sub_op_bits(&insn.mnemonic) {
        if !(0..=0x7F).contains(&count_value) {
            return Err(AsmError::new(
                line,
                insn.mnemonic_col,
                format!(
                    "`{}` count {count_value} out of range (0..=0x7F)",
                    insn.mnemonic
                ),
            ));
        }
        ((count_value as u8) | sub_bits) as i8
    } else {
        if !(-128..=127).contains(&count_value) {
            return Err(AsmError::new(
                line,
                insn.mnemonic_col,
                format!(
                    "displacement {count_value} out of range for short form (-128..=127); use `L` to force long form"
                ),
            ));
        }
        count_value as i8
    };
    Ok(Instruction::Short {
        op,
        tag: insn.tag,
        disp: disp_value,
    })
}

fn build_long(
    insn: &crate::parser::Instruction,
    op: Opcode,
    symbols: &SymbolTable,
    lc: i64,
    line: u32,
) -> Result<Instruction, AsmError> {
    let address = match &insn.operand {
        Some(o) => resolve(o, symbols, lc, line)?,
        None => 0,
    };
    if !(-32768..=65535).contains(&address) {
        return Err(AsmError::new(
            line,
            insn.mnemonic_col,
            format!("address {address} out of range for long form (16-bit)"),
        ));
    }
    let mask = if let Some(fixed) = alias_mask(&insn.mnemonic) {
        // The mnemonic bakes in a condition mask (e.g. BZ, BNZ).
        // Reject user-supplied masks -- the alias's whole point is
        // to be a convenient name for a specific mask.
        if insn.mask.is_some() {
            return Err(AsmError::new(
                line,
                insn.mnemonic_col,
                format!(
                    "`{}` is a mnemonic alias with a built-in mask; remove the mask operand",
                    insn.mnemonic
                ),
            ));
        }
        fixed
    } else {
        match &insn.mask {
            Some(o) => {
                let v = resolve(o, symbols, lc, line)?;
                if !accepts_mask(&insn.mnemonic) {
                    return Err(AsmError::new(
                        line,
                        insn.mnemonic_col,
                        format!(
                            "`{}` long form does not accept a condition mask (mask is BSC/BSI only)",
                            insn.mnemonic
                        ),
                    ));
                }
                if !(0..=0x7F).contains(&v) {
                    return Err(AsmError::new(
                        line,
                        insn.mnemonic_col,
                        format!("condition mask {v:#x} out of range (0..=0x7F)"),
                    ));
                }
                v as u8
            }
            None => 0,
        }
    };
    Ok(Instruction::Long {
        op,
        tag: insn.tag,
        indirect: insn.indirect_flag,
        mask,
        address: address as u16,
    })
}

/// Mnemonics whose long form accepts a condition mask. Per the 1130
/// FC manual and Moore's 1968 source: BSC and BSI. All other
/// long-form opcodes must have mask = 0.
fn accepts_mask(mnem: &str) -> bool {
    matches!(mnem, "bsc" | "bsi")
}

/// Conditional-branch mnemonic aliases. Each maps to BSC long form
/// with a fixed mask byte; the user does NOT supply a mask
/// operand. Mask bit assignments per Moore's 1968 FORTH listing:
/// 0x04=Even, 0x08=Positive, 0x10=Negative, 0x20=Zero, 0x40=Carry.
fn alias_mask(mnem: &str) -> Option<u8> {
    match mnem {
        "b" | "bl" => Some(0), // unconditional
        "bz" => Some(0x20),    // Z
        "bnz" => Some(0x18),   // P | N  (= not Z)
        "bp" => Some(0x08),    // +
        "bn" => Some(0x10),    // -
        "bnp" => Some(0x28),   // - | Z  (= not +)
        "bod" => Some(0x04),   // E (Moore's :EVEN value; 'OD' is the
        // historical 1130 'on data' / odd
        // mnemonic. Verify against actual
        // FC manual semantics during step 5.)
        _ => None,
    }
}

/// Shift sub-op mnemonics: SLT (shift left together), SRT (shift
/// right together). Both shift the (ACC, EXT) pair as a 32-bit
/// value. Returns the sub-op bit pattern OR'd into the disp byte.
fn shift_sub_op_bits(mnem: &str) -> Option<u8> {
    match mnem {
        "slt" | "srt" => Some(0x80),
        _ => None,
    }
}

fn resolve(op: &Operand, symbols: &SymbolTable, lc: i64, line: u32) -> Result<i64, AsmError> {
    match op {
        Operand::Number(n) => Ok(*n),
        Operand::Symbol(name) => symbols
            .lookup(name)
            .ok_or_else(|| AsmError::new(line, 1, format!("undefined symbol `{name}`"))),
        Operand::LocationCounter => Ok(lc),
        Operand::Offset { base, delta } => {
            let v = resolve(base, symbols, lc, line)?;
            Ok(v + *delta)
        }
        Operand::Multiply { lhs, rhs } => {
            let v = resolve(rhs, symbols, lc, line)?;
            Ok(*lhs * v)
        }
    }
}

/// Map a lowercased mnemonic to its `Opcode`. Anything not in the
/// known set produces a structured error.
fn mnemonic_to_opcode(mnem: &str, line: u32, col: u32) -> Result<Opcode, AsmError> {
    Ok(match mnem {
        "ld" => Opcode::Load,
        "ldd" => Opcode::LoadDouble,
        "sto" => Opcode::Store,
        "std" => Opcode::StoreDouble,
        "ldx" => Opcode::LoadIndex,
        "stx" => Opcode::StoreIndex,
        "lds" => Opcode::LoadStatus,
        "sts" => Opcode::StoreStatus,
        "a" => Opcode::Add,
        "ad" => Opcode::AddDouble,
        "s" => Opcode::Subtract,
        "sd" => Opcode::SubtractDouble,
        "m" => Opcode::Multiply,
        "d" => Opcode::Divide,
        "and" => Opcode::And,
        "or" => Opcode::Or,
        "eor" => Opcode::ExclusiveOr,
        "sla" => Opcode::ShiftLeft,
        "slt" => Opcode::ShiftLeft, // sub-op of SLA
        "sra" => Opcode::ShiftRight,
        "srt" => Opcode::ShiftRight, // sub-op of SRA
        "bsc" => Opcode::BranchSkipCondition,
        "bsi" => Opcode::BranchStore,
        "mdx" => Opcode::ModifyIndex,
        "wait" => Opcode::Wait,
        "xio" => Opcode::ExecuteInputOutput,
        // Conditional-branch aliases (mapped to BSC; mask baked in
        // via alias_mask). All are long-form-only.
        "b" | "bl" | "bz" | "bnz" | "bp" | "bn" | "bnp" | "bod" => Opcode::BranchSkipCondition,
        _ => {
            return Err(AsmError::new(
                line,
                col,
                format!("unknown mnemonic `{mnem}`"),
            ));
        }
    })
}

/// Mnemonics that have only the long form. Includes the
/// conditional-branch aliases (BZ/BNZ/etc) which are long-form by
/// definition.
pub fn is_long_only(mnem: &str) -> bool {
    matches!(
        mnem,
        "xio" | "b" | "bl" | "bz" | "bnz" | "bp" | "bn" | "bnp" | "bod"
    )
}

/// Mnemonics that have only the short form.
pub fn is_short_only(mnem: &str) -> bool {
    matches!(mnem, "wait" | "sla" | "sra" | "slt" | "srt")
}
