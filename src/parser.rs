//! Lexer + line parser for the 1130 asm.
//!
//! The parser is line-oriented: each non-empty, non-comment line is
//! either a directive or an instruction, optionally preceded by a
//! label. Lines compile-down to a `ParsedLine` carrying source
//! position so pass 1 / pass 2 errors can report `line:col`.

use crate::AsmError;

/// One source line after parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedLine {
    /// 1-based line number.
    pub line: u32,
    pub label: Option<Label>,
    pub body: LineBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub name: String,
    pub col: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineBody {
    Empty,
    Directive(Directive),
    Instruction(Instruction),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Directive {
    /// `ORG N` -- set assembly origin to word address N.
    Org(Operand),
    /// `LABEL EQU N` -- bind label to numeric value.
    Equ(Operand),
    /// `DC N` -- emit one literal word.
    Dc(Operand),
    /// `BSS N` -- reserve N words at the current location counter
    /// (emits N zero words). The label, if any, binds to the
    /// pre-advance LC value.
    Bss(Operand),
    /// `ABS` -- absolute (non-relocatable) program marker. No-op
    /// for us (we don't relocate); accepted for compatibility with
    /// historical 1130 source.
    Abs,
    /// `END [LABEL]` -- end of source; the optional operand names
    /// the program's entry point. Stored but not currently emitted
    /// in the output.
    End(Option<Operand>),
}

/// Parsed instruction body; address resolution happens in pass 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub mnemonic: String,
    pub mnemonic_col: u32,
    pub long_flag: bool,
    pub indirect_flag: bool,
    pub tag: u8,
    /// Primary operand (address / displacement / immediate).
    pub operand: Option<Operand>,
    /// Secondary operand (BSC mask in long form).
    pub mask: Option<Operand>,
}

/// An operand expression.
///
/// Most operands are a bare `Number` or `Symbol`. The `*`
/// (location-counter) sentinel and small `±N` offsets are supported
/// for compatibility with the historical 1130 source style
/// (`SYM+1`, `*-2`, etc.). Full expression parsing (multi-term
/// arithmetic) is out of scope; the offset form covers Moore's
/// actual usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    Number(i64),
    Symbol(String),
    /// `*` -- the current pass-2 location counter.
    LocationCounter,
    /// `base + delta` (or `base - delta` with delta negated).
    Offset {
        base: Box<Operand>,
        delta: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperandWithCol {
    pub op: Operand,
    pub col: u32,
}

/// Parse the entire source. Pre-scans every line; pass 1 / pass 2
/// can iterate over the result without re-lexing.
pub fn parse_source(source: &str) -> Result<Vec<ParsedLine>, AsmError> {
    let mut out = Vec::new();
    for (idx, raw) in source.lines().enumerate() {
        let line = (idx + 1) as u32;
        out.push(parse_line(line, raw)?);
    }
    Ok(out)
}

/// Parse a single line.
fn parse_line(line: u32, src: &str) -> Result<ParsedLine, AsmError> {
    // Strip trailing comment first.
    let src = strip_comment(src);
    if src.trim().is_empty() {
        return Ok(ParsedLine {
            line,
            label: None,
            body: LineBody::Empty,
        });
    }

    // Whole-line comments from historical 1130 source:
    //   "// JOB", "// ASM"        -- 1130 monitor job-card directives
    //   "*LIST ALL", "*..."       -- asm listing-output directives
    // Treat the line as empty.
    let trimmed = src.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with('*') {
        // Note: `*` as a comment-line marker is unambiguous because
        // `*` in an operand position (current LC) is only ever read
        // inside parse_operand, not at line start.
        return Ok(ParsedLine {
            line,
            label: None,
            body: LineBody::Empty,
        });
    }

    let mut cursor = Cursor::new(line, src);
    cursor.skip_whitespace();

    // A label is an identifier followed by `:`. We probe by reading
    // the first token and looking ahead: if it ends with a colon, it
    // is a label; otherwise rewind and treat as a mnemonic. This
    // makes column-1 placement irrelevant -- modern asm style.
    let label = {
        let saved_pos = cursor.pos;
        let saved_col = cursor.col;
        if let Some(name) = cursor.read_ident() {
            if cursor.peek_byte() == Some(b':') {
                let col = saved_col;
                cursor.advance(1);
                Some(Label { name, col })
            } else {
                cursor.pos = saved_pos;
                cursor.col = saved_col;
                None
            }
        } else {
            None
        }
    };

    cursor.skip_whitespace();
    if cursor.eof() {
        return Ok(ParsedLine {
            line,
            label,
            body: LineBody::Empty,
        });
    }

    // Mnemonic / directive name.
    let mnemonic_col = cursor.col;
    let raw_mnemonic = cursor
        .read_ident()
        .ok_or_else(|| AsmError::new(line, mnemonic_col, "expected mnemonic or directive"))?;
    let mnemonic = raw_mnemonic.to_ascii_lowercase();

    let body = match mnemonic.as_str() {
        "org" => {
            let op = parse_one_operand(&mut cursor)?;
            LineBody::Directive(Directive::Org(op))
        }
        "equ" => {
            let op = parse_one_operand(&mut cursor)?;
            LineBody::Directive(Directive::Equ(op))
        }
        "dc" => {
            let op = parse_one_operand(&mut cursor)?;
            LineBody::Directive(Directive::Dc(op))
        }
        "bss" => {
            let op = parse_one_operand(&mut cursor)?;
            LineBody::Directive(Directive::Bss(op))
        }
        "abs" => LineBody::Directive(Directive::Abs),
        "end" => {
            cursor.skip_whitespace();
            let entry = if cursor.eof() {
                None
            } else {
                Some(parse_one_operand(&mut cursor)?)
            };
            LineBody::Directive(Directive::End(entry))
        }
        _ => parse_instruction(&mut cursor, mnemonic, mnemonic_col)?,
    };

    cursor.skip_whitespace();
    if !cursor.eof() {
        return Err(AsmError::new(
            line,
            cursor.col,
            format!("unexpected trailing input: {:?}", cursor.rest()),
        ));
    }

    Ok(ParsedLine { line, label, body })
}

fn parse_instruction(
    cursor: &mut Cursor,
    mnemonic: String,
    mnemonic_col: u32,
) -> Result<LineBody, AsmError> {
    cursor.skip_whitespace();
    let mut long_flag = false;
    let mut indirect_flag = false;
    let mut tag: u8 = 0;
    let mut operand: Option<Operand> = None;
    let mut mask: Option<Operand> = None;

    // Read flag tokens 'I' / 'L' (case-insensitive). We accept any
    // mix; `I` implies long form regardless. To avoid eating the
    // operand (which may itself be named `I` or `L`), only consume
    // an `I`/`L` token as a flag if there is at least one more
    // token after it on the line.
    loop {
        cursor.skip_whitespace();
        let saved = cursor.pos;
        let saved_col = cursor.col;
        match cursor.read_ident() {
            Some(ident) => {
                let lower = ident.to_ascii_lowercase();
                let is_flag_candidate = matches!(lower.as_str(), "i" | "l");
                if !is_flag_candidate {
                    cursor.pos = saved;
                    cursor.col = saved_col;
                    break;
                }
                // Peek ahead: is there more input after this token?
                // If not, this token is the operand, not a flag.
                let mut probe = cursor.pos;
                while probe < cursor.src.len() {
                    let b = cursor.src.as_bytes()[probe];
                    if b == b' ' || b == b'\t' {
                        probe += 1;
                    } else {
                        break;
                    }
                }
                if probe >= cursor.src.len() {
                    // No more tokens -- treat as operand.
                    cursor.pos = saved;
                    cursor.col = saved_col;
                    break;
                }
                match lower.as_str() {
                    "i" => indirect_flag = true,
                    "l" => long_flag = true,
                    _ => unreachable!(),
                }
            }
            None => break,
        }
    }

    cursor.skip_whitespace();
    if cursor.eof() {
        // Mnemonic with no operand; legal for `wait`.
        return Ok(LineBody::Instruction(Instruction {
            mnemonic,
            mnemonic_col,
            long_flag,
            indirect_flag,
            tag,
            operand,
            mask,
        }));
    }

    // Optional `TAG,` prefix where TAG is a digit 0..=3 followed by a
    // comma. We disambiguate by peeking: if we see a single decimal
    // digit followed by `,` and the digit is in 0..=3, it's a tag.
    if is_tag_prefix(cursor.rest()) {
        let digit = cursor.peek_byte().unwrap() - b'0';
        cursor.advance(1);
        // skip optional whitespace before comma
        cursor.skip_whitespace();
        // consume the comma
        if cursor.peek_byte() == Some(b',') {
            cursor.advance(1);
        }
        tag = digit;
        cursor.skip_whitespace();
    }

    // Primary operand.
    if !cursor.eof() {
        operand = Some(parse_operand(cursor)?);
        cursor.skip_whitespace();
        // Optional `, MASK` for BSC long form.
        if cursor.peek_byte() == Some(b',') {
            cursor.advance(1);
            cursor.skip_whitespace();
            mask = Some(parse_operand(cursor)?);
        }
    }

    Ok(LineBody::Instruction(Instruction {
        mnemonic,
        mnemonic_col,
        long_flag,
        indirect_flag,
        tag,
        operand,
        mask,
    }))
}

fn is_tag_prefix(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let d = bytes[0];
    if !(b'0'..=b'3').contains(&d) {
        return false;
    }
    // Allow `N,` or `N ,` (whitespace before comma).
    let mut i = 1;
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    i < bytes.len() && bytes[i] == b','
}

fn parse_one_operand(cursor: &mut Cursor) -> Result<Operand, AsmError> {
    cursor.skip_whitespace();
    parse_operand(cursor)
}

fn parse_operand(cursor: &mut Cursor) -> Result<Operand, AsmError> {
    let col = cursor.col;
    let token = cursor
        .read_operand_token()
        .ok_or_else(|| AsmError::new(cursor.line, col, "expected operand (number or symbol)"))?;
    parse_operand_text(cursor.line, col, &token)
}

/// Try to split an operand token into a base term plus an optional
/// `±N` offset. Handles forms like `SYM+1`, `*-2`, `0x10+5`, etc.
/// The split point is the LAST `+` or `-` that is not part of a
/// leading sign or a hex/decimal literal's leading sign and whose
/// right-hand side parses as a number.
fn split_offset(text: &str) -> Option<(&str, i64)> {
    // Look for a `+` or `-` after position 0 (so a leading `-` is
    // not split off). We scan from the right so chains like
    // `A+B+1` would prefer the rightmost split; but multi-term
    // chains aren't supported anyway.
    let bytes = text.as_bytes();
    for i in (1..bytes.len()).rev() {
        let b = bytes[i];
        if b != b'+' && b != b'-' {
            continue;
        }
        // The byte before this must NOT be another sign-like
        // character (would mean a two-char `+-` etc.) or the start
        // of a hex/octal/binary prefix where the sign belongs to
        // the literal. Simplest rule: split only when the prior
        // byte is alphanumeric or `_` or `*`. That covers
        // `SYM+1` and `*-2` and rules out `0x-1`.
        let prev = bytes[i - 1];
        if !(prev.is_ascii_alphanumeric() || prev == b'_' || prev == b'.' || prev == b'*') {
            continue;
        }
        let lhs = &text[..i];
        let rhs = &text[i..]; // includes sign
        let delta = parse_number(rhs)?;
        return Some((lhs.trim_end(), delta));
    }
    None
}

fn parse_operand_text(line: u32, col: u32, text: &str) -> Result<Operand, AsmError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(AsmError::new(line, col, "empty operand"));
    }
    // Offset form: split off a trailing `±N` if present.
    if let Some((lhs, delta)) = split_offset(trimmed) {
        let base = parse_operand_text(line, col, lhs)?;
        return Ok(Operand::Offset {
            base: Box::new(base),
            delta,
        });
    }
    // `*` = current location counter (pass-2-resolved).
    if trimmed == "*" {
        return Ok(Operand::LocationCounter);
    }
    if let Some(n) = parse_number(trimmed) {
        return Ok(Operand::Number(n));
    }
    if is_ident_start(trimmed.as_bytes()[0])
        && trimmed
            .bytes()
            .all(|b| is_ident_start(b) || b.is_ascii_digit())
    {
        return Ok(Operand::Symbol(trimmed.to_string()));
    }
    Err(AsmError::new(
        line,
        col,
        format!("invalid operand: {trimmed:?}"),
    ))
}

fn parse_number(s: &str) -> Option<i64> {
    let (sign, body): (i64, &str) = if let Some(stripped) = s.strip_prefix('-') {
        (-1, stripped)
    } else if let Some(stripped) = s.strip_prefix('+') {
        (1, stripped)
    } else {
        (1, s)
    };
    let body = body.trim();
    let n = if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()?
    } else if let Some(hex) = body.strip_prefix('/') {
        // Historical 1130 asm hex literal: `/XXX` = hex value.
        i64::from_str_radix(hex, 16).ok()?
    } else if let Some(bin) = body.strip_prefix("0b").or_else(|| body.strip_prefix("0B")) {
        i64::from_str_radix(bin, 2).ok()?
    } else if !body.is_empty() && body.bytes().all(|b| b.is_ascii_digit()) {
        body.parse::<i64>().ok()?
    } else {
        return None;
    };
    Some(sign * n)
}

fn strip_comment(s: &str) -> &str {
    s.split(';').next().unwrap_or("").trim_end()
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b'.'
}

/// Cursor over one source line.
struct Cursor<'a> {
    line: u32,
    src: &'a str,
    pos: usize,
    /// 1-based column of `pos`.
    col: u32,
}

impl<'a> Cursor<'a> {
    fn new(line: u32, src: &'a str) -> Self {
        Self {
            line,
            src,
            pos: 0,
            col: 1,
        }
    }

    fn rest(&self) -> &'a str {
        &self.src[self.pos..]
    }

    fn eof(&self) -> bool {
        self.pos >= self.src.len()
    }

    fn peek_byte(&self) -> Option<u8> {
        self.src.as_bytes().get(self.pos).copied()
    }

    fn advance(&mut self, n: usize) {
        for _ in 0..n {
            if self.pos < self.src.len() {
                self.pos += 1;
                self.col += 1;
            }
        }
    }

    fn skip_whitespace(&mut self) {
        while let Some(b) = self.peek_byte() {
            if b == b' ' || b == b'\t' {
                self.advance(1);
            } else {
                break;
            }
        }
    }

    fn read_ident(&mut self) -> Option<String> {
        let start = self.pos;
        let first = self.peek_byte()?;
        if !is_ident_start(first) {
            return None;
        }
        self.advance(1);
        while let Some(b) = self.peek_byte() {
            if is_ident_start(b) || b.is_ascii_digit() {
                self.advance(1);
            } else {
                break;
            }
        }
        Some(self.src[start..self.pos].to_string())
    }

    /// Read a single operand token: a number (with optional sign and
    /// optional 0x prefix) or a bare identifier.
    fn read_operand_token(&mut self) -> Option<String> {
        let start = self.pos;
        // Optional sign.
        if let Some(b) = self.peek_byte()
            && (b == b'+' || b == b'-')
        {
            self.advance(1);
        }
        let body_start = self.pos;
        while let Some(b) = self.peek_byte() {
            if b == b' ' || b == b'\t' || b == b',' {
                break;
            }
            self.advance(1);
        }
        if self.pos == body_start {
            return None;
        }
        Some(self.src[start..self.pos].to_string())
    }
}
