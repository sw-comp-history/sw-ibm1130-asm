//! Disassembler: bytes -> textual asm.
//!
//! The output is the round-trip-stable form: re-parsing it should
//! produce instructions whose encoded bytes equal the input. Names
//! are not recovered (we never had them in the byte stream); operands
//! are emitted as numeric literals.

use sw_ibm1130_isa::{Instruction, decode};

use crate::AsmError;

/// Disassemble a byte stream into asm text. Each instruction
/// becomes one line. Errors mid-stream are reported with a virtual
/// "line" matching the instruction index (1-based).
pub fn disassemble(bytes: &[u8]) -> Result<String, AsmError> {
    let mut out = String::new();
    let mut offset = 0;
    let mut idx: u32 = 1;
    while offset < bytes.len() {
        let (insn, n) = decode::decode(&bytes[offset..])
            .map_err(|e| AsmError::new(idx, 1, format!("decode failed at byte {offset}: {e:?}")))?;
        out.push_str(&render_instruction(&insn));
        out.push('\n');
        offset += n;
        idx += 1;
    }
    Ok(out)
}

/// Render one decoded instruction into a single asm line.
pub fn render_instruction(insn: &Instruction) -> String {
    match insn {
        Instruction::Short { op, tag, disp } => {
            let mnem = op.mnemonic();
            if *tag == 0 {
                format!("        {} {}", mnem, disp)
            } else {
                format!("        {} {},{}", mnem, tag, disp)
            }
        }
        Instruction::Long {
            op,
            tag,
            indirect,
            address,
        } => {
            let mnem = op.mnemonic();
            let mut s = String::from("        ");
            s.push_str(mnem);
            s.push(' ');
            s.push('L');
            if *indirect {
                s.push_str(" I");
            }
            s.push(' ');
            if *tag != 0 {
                s.push_str(&tag.to_string());
                s.push(',');
            }
            s.push_str(&format!("0x{:04x}", address));
            s
        }
    }
}
