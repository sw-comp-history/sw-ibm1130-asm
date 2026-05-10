//! `sw-ibm1130-asm`: IBM 1130 two-pass assembler.
//!
//! Source format (one line per record, ASCII only):
//!
//! ```text
//! ; full-line comment
//! LABEL    MNEMONIC [I] [L] [TAG,] EXPR [, MASK]   ; trailing comment
//! LABEL    DC       EXPR
//! LABEL    EQU      NUMBER
//!          ORG      NUMBER
//!          END
//! ```
//!
//! - `I`  -- indirect addressing flag (forces long form).
//! - `L`  -- explicit long-form flag.
//! - `TAG`-- index-register tag, 0..=3 (0 = no XR; 1..=3 = XR1..XR3).
//! - `EXPR` -- a number (`123`, `0xFF`, `-7`) or a symbol name.
//! - `MASK` -- BSC condition mask (long form); for short BSC the
//!   "address/disp" operand IS the mask byte directly.
//!
//! Format selection: the assembler picks short form when the
//! displacement fits in `[-128, 127]` and no `I`/`L` flag is set;
//! long form otherwise. `WAIT` is short-only; `XIO` is long-only.
//!
//! The asm's job is text -> bytes via `sw_ibm1130_isa::encode`.
//! Round-trip discipline (text -> bytes -> decoded -> bytes) is the
//! integration-test contract.

pub mod disasm;
pub mod encode;
pub mod parser;
pub mod symtab;

pub use disasm::disassemble;
pub use parser::{Directive, Operand, ParsedLine, parse_source};
pub use symtab::SymbolTable;

use sw_ibm1130_isa::Instruction;

/// An assembly error with source position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsmError {
    /// 1-based line number.
    pub line: u32,
    /// 1-based column.
    pub col: u32,
    pub message: String,
}

impl AsmError {
    pub fn new(line: u32, col: u32, message: impl Into<String>) -> Self {
        Self {
            line,
            col,
            message: message.into(),
        }
    }
}

impl core::fmt::Display for AsmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.col, self.message)
    }
}

impl std::error::Error for AsmError {}

/// Output of a successful assembly: the encoded byte stream and the
/// final symbol table (for caller-side disassembly / linking).
#[derive(Debug, Clone)]
pub struct AsmOutput {
    pub bytes: Vec<u8>,
    pub symbols: SymbolTable,
    /// Decoded instruction stream parallel to `bytes`. Useful for
    /// tests that want to round-trip without re-decoding.
    pub instructions: Vec<Instruction>,
}

/// Assemble source text into bytes + symbol table.
pub fn assemble(source: &str) -> Result<AsmOutput, AsmError> {
    let lines = parser::parse_source(source)?;
    let symbols = symtab::build_pass1(&lines)?;
    encode::emit_pass2(&lines, &symbols)
}
