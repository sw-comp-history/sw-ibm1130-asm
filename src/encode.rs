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
                    let v = resolve(op, symbols, line.line)?;
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
                    let v = resolve(op, symbols, line.line)?;
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
                Directive::End => break,
            },
            LineBody::Instruction(insn) => {
                let opcode = mnemonic_to_opcode(&insn.mnemonic, line.line, insn.mnemonic_col)?;
                let force_short = is_short_only(&insn.mnemonic);
                let want_long =
                    (insn.long_flag || insn.indirect_flag || is_long_only(&insn.mnemonic))
                        && !force_short;

                if force_short && (insn.long_flag || insn.indirect_flag) {
                    return Err(AsmError::new(
                        line.line,
                        insn.mnemonic_col,
                        format!("`{}` has no long form", insn.mnemonic),
                    ));
                }

                let built = if want_long {
                    build_long(insn, opcode, symbols, line.line)?
                } else {
                    build_short(insn, opcode, symbols, line.line)?
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
    line: u32,
) -> Result<Instruction, AsmError> {
    let disp_value = match &insn.operand {
        Some(o) => resolve(o, symbols, line)?,
        None => 0,
    };
    if !(-128..=127).contains(&disp_value) {
        return Err(AsmError::new(
            line,
            insn.mnemonic_col,
            format!(
                "displacement {disp_value} out of range for short form (-128..=127); use `L` to force long form"
            ),
        ));
    }
    Ok(Instruction::Short {
        op,
        tag: insn.tag,
        disp: disp_value as i8,
    })
}

fn build_long(
    insn: &crate::parser::Instruction,
    op: Opcode,
    symbols: &SymbolTable,
    line: u32,
) -> Result<Instruction, AsmError> {
    let address = match &insn.operand {
        Some(o) => resolve(o, symbols, line)?,
        None => 0,
    };
    if !(-32768..=65535).contains(&address) {
        return Err(AsmError::new(
            line,
            insn.mnemonic_col,
            format!("address {address} out of range for long form (16-bit)"),
        ));
    }
    let mask = match &insn.mask {
        Some(o) => {
            let v = resolve(o, symbols, line)?;
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

fn resolve(op: &Operand, symbols: &SymbolTable, line: u32) -> Result<i64, AsmError> {
    match op {
        Operand::Number(n) => Ok(*n),
        Operand::Symbol(name) => symbols
            .lookup(name)
            .ok_or_else(|| AsmError::new(line, 1, format!("undefined symbol `{name}`"))),
    }
}

/// Map a lowercased mnemonic to its `Opcode`. Anything not in the
/// 24-mnemonic set produces a structured error.
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
        "sra" => Opcode::ShiftRight,
        "bsc" => Opcode::BranchSkipCondition,
        "bsi" => Opcode::BranchStore,
        "mdx" => Opcode::ModifyIndex,
        "wait" => Opcode::Wait,
        "xio" => Opcode::ExecuteInputOutput,
        _ => {
            return Err(AsmError::new(
                line,
                col,
                format!("unknown mnemonic `{mnem}`"),
            ));
        }
    })
}

/// Mnemonics that have only the long form (per `docs/spec-examples/
/// ibm1130.toml` formats lists).
pub fn is_long_only(mnem: &str) -> bool {
    matches!(mnem, "xio")
}

/// Mnemonics that have only the short form.
pub fn is_short_only(mnem: &str) -> bool {
    matches!(mnem, "wait" | "sla" | "sra")
}
