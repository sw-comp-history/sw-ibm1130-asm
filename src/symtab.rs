//! Symbol table + pass 1.
//!
//! Pass 1 walks the parsed line list, tracks the location counter
//! through each line's emitted size, and binds labels:
//!
//! - Bare `LABEL:` (or `LABEL` in column 1 with no body) -- bind to
//!   the current location counter.
//! - `LABEL EQU NUMBER` -- bind to the literal number.
//! - `LABEL DC ...` -- bind to current LC, then emit one word.
//! - `LABEL <instr>` -- bind to current LC, then emit instruction.
//! - `ORG N` -- set LC to N.
//!
//! The table is `HashMap<String, i64>` so EQUs that store negative
//! values or 17-bit constants are representable; truncation to u16
//! happens at encode time.

use std::collections::HashMap;

use crate::AsmError;
use crate::parser::{Directive, LineBody, Operand, ParsedLine};

/// A bound symbol with its definition site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolDef {
    pub value: i64,
    pub line: u32,
    pub col: u32,
}

#[derive(Debug, Clone, Default)]
pub struct SymbolTable {
    pub map: HashMap<String, SymbolDef>,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lookup(&self, name: &str) -> Option<i64> {
        self.map.get(name).map(|d| d.value)
    }

    pub fn define(&mut self, name: &str, value: i64, line: u32, col: u32) -> Result<(), AsmError> {
        if let Some(prev) = self.map.get(name) {
            return Err(AsmError::new(
                line,
                col,
                format!(
                    "duplicate label `{name}`; previously defined at line {}",
                    prev.line
                ),
            ));
        }
        self.map
            .insert(name.to_string(), SymbolDef { value, line, col });
        Ok(())
    }
}

/// Pass 1: build the symbol table by walking lines and tracking the
/// location counter.
pub fn build_pass1(lines: &[ParsedLine]) -> Result<SymbolTable, AsmError> {
    let mut symtab = SymbolTable::new();
    let mut lc: i64 = 0;

    for line in lines {
        match &line.body {
            LineBody::Empty => {
                if let Some(label) = &line.label {
                    symtab.define(&label.name, lc, line.line, label.col)?;
                }
            }
            LineBody::Directive(d) => match d {
                Directive::Org(op) => {
                    if let Some(label) = &line.label {
                        return Err(AsmError::new(
                            line.line,
                            label.col,
                            "ORG cannot have a label",
                        ));
                    }
                    let v = resolve_pass1(op, &symtab, lc, line.line)?;
                    lc = v;
                }
                Directive::Equ(op) => {
                    let label = line
                        .label
                        .as_ref()
                        .ok_or_else(|| AsmError::new(line.line, 1, "EQU requires a label"))?;
                    let v = resolve_pass1(op, &symtab, lc, line.line)?;
                    symtab.define(&label.name, v, line.line, label.col)?;
                }
                Directive::Dc(_) => {
                    if let Some(label) = &line.label {
                        symtab.define(&label.name, lc, line.line, label.col)?;
                    }
                    lc += 1;
                }
                Directive::Bss(op) => {
                    if let Some(label) = &line.label {
                        symtab.define(&label.name, lc, line.line, label.col)?;
                    }
                    let n = resolve_pass1(op, &symtab, lc, line.line)?;
                    if n < 0 {
                        return Err(AsmError::new(
                            line.line,
                            1,
                            format!("BSS size must be non-negative; got {n}"),
                        ));
                    }
                    lc += n;
                }
                Directive::Abs => {
                    // ABS is a no-op marker: declares the program
                    // as non-relocatable. We don't relocate.
                    if let Some(label) = &line.label {
                        symtab.define(&label.name, lc, line.line, label.col)?;
                    }
                }
                Directive::End(_entry) => {
                    if let Some(label) = &line.label {
                        symtab.define(&label.name, lc, line.line, label.col)?;
                    }
                    break;
                }
            },
            LineBody::Instruction(insn) => {
                if let Some(label) = &line.label {
                    symtab.define(&label.name, lc, line.line, label.col)?;
                }
                lc += instruction_size_words(insn);
            }
        }
    }

    Ok(symtab)
}

/// Words emitted by an instruction (1 = short, 2 = long). Matches
/// the rules used by encode::emit_pass2.
pub(crate) fn instruction_size_words(insn: &crate::parser::Instruction) -> i64 {
    use crate::encode::is_long_only;
    use crate::encode::is_short_only;

    if is_short_only(&insn.mnemonic) {
        return 1;
    }
    if is_long_only(&insn.mnemonic) {
        return 2;
    }
    if insn.long_flag || insn.indirect_flag {
        return 2;
    }
    // Default: short. Pass 2 may promote when displacement is out of
    // range, but that requires knowing the operand value, which in
    // general isn't known until pass 1 has finished. For predictable
    // sizing we require the user to mark long form explicitly with
    // `L` or `I` when the operand is a large symbol; otherwise pass
    // 2 will try short and error on out-of-range.
    1
}

/// Resolve an operand during pass 1. Symbols must already be in the
/// symbol table (forward references in `ORG` / `EQU` expressions
/// are not supported).
fn resolve_pass1(op: &Operand, symtab: &SymbolTable, lc: i64, line: u32) -> Result<i64, AsmError> {
    match op {
        Operand::Number(n) => Ok(*n),
        Operand::Symbol(name) => symtab.lookup(name).ok_or_else(|| {
            AsmError::new(
                line,
                1,
                format!("undefined symbol `{name}` (forward references not allowed in pass 1)"),
            )
        }),
        Operand::LocationCounter => Ok(lc),
        Operand::Offset { base, delta } => {
            let v = resolve_pass1(base, symtab, lc, line)?;
            Ok(v + *delta)
        }
    }
}
