//! Generate a native grammar-based mutator from a small BNF grammar.
//!
//! The output is one C translation unit (also valid C++) that defines the
//! selected engine's native mutation callbacks. Nothing is loaded or executed
//! on the host: the generated source goes through the managed-mutator import,
//! review, smoke and promotion workflow like hand-written source, so every
//! byte that later runs is the text a reviewer was shown.
//!
//! Grammar syntax:
//!
//! ```text
//! # the first rule is the start rule
//! value  = object | array | "true" | "null" | number ;
//! object = "{" "}" | "{" pair "}" ;
//! pair   = "\"k\":" value ;
//! array  = "[" "]" | "[" value "," value "]" ;
//! number = "0" | "-1" | "1e9" ;
//! ```
//!
//! A terminal is a double-quoted string with `\\`, `\"`, `\n`, `\r`, `\t`,
//! `\0` and `\xNN` escapes. An alternative with no symbols produces nothing.

use std::collections::HashMap;
use std::fmt::Write as _;

use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;

/// Grammar text accepted.
const MAX_GRAMMAR_BYTES: usize = 64 * 1024;
const MAX_RULES: usize = 256;
const MAX_ALTERNATIVES: usize = 2048;
const MAX_SYMBOLS: usize = 8192;
const MAX_TERMINALS: usize = 2048;
const MAX_TERMINAL_BYTES: usize = 16 * 1024;
/// Generated source accepted: the managed-mutator envelope allows 64 KiB for
/// the base harness and the mutator together.
const MAX_GENERATED_BYTES: usize = 40 * 1024;

fn invalid(message: impl AsRef<str>) -> ClassifiedError {
    ClassifiedError::Validation(format!("grammar mutator: {}", message.as_ref()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Symbol {
    Terminal(usize),
    Rule(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Name(String),
    Text(Vec<u8>),
    Equals,
    Bar,
    Semicolon,
}

/// A validated grammar: every rule is defined once and can terminate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grammar {
    names: Vec<String>,
    /// Per rule, its alternatives; per alternative, its symbols.
    rules: Vec<Vec<Vec<Symbol>>>,
    terminals: Vec<Vec<u8>>,
    /// Per rule, the index of the alternative that terminates in the fewest
    /// expansions.
    shortest: Vec<usize>,
}

impl Grammar {
    /// Number of rules.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Parse and validate grammar text.
    ///
    /// # Errors
    /// Returns [`ClassifiedError::Validation`] naming the line for a syntax
    /// error, and naming the rule for an undefined or duplicate rule or one
    /// that can never terminate. Size limits are errors too.
    pub fn parse(text: &str) -> Result<Self, ClassifiedError> {
        if text.len() > MAX_GRAMMAR_BYTES {
            return Err(invalid("grammar text exceeds 64 KiB"));
        }
        let tokens = tokenize(text)?;
        let parsed = parse_rules(&tokens)?;
        let mut index: HashMap<&str, usize> = HashMap::new();
        for (position, (name, line, _)) in parsed.iter().enumerate() {
            if index.insert(name.as_str(), position).is_some() {
                return Err(invalid(format!(
                    "line {line}: rule '{name}' is defined twice"
                )));
            }
        }
        if parsed.is_empty() {
            return Err(invalid("the grammar defines no rule"));
        }
        if parsed.len() > MAX_RULES {
            return Err(invalid(format!("more than {MAX_RULES} rules")));
        }
        let mut terminals: Vec<Vec<u8>> = Vec::new();
        let mut terminal_index: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut rules = Vec::with_capacity(parsed.len());
        let (mut alternatives, mut symbols) = (0_usize, 0_usize);
        for (_, line, alts) in &parsed {
            let mut rule = Vec::with_capacity(alts.len());
            for alt in alts {
                let mut out = Vec::with_capacity(alt.len());
                for token in alt {
                    out.push(match token {
                        Token::Name(name) => {
                            Symbol::Rule(*index.get(name.as_str()).ok_or_else(|| {
                                invalid(format!("line {line}: rule '{name}' is not defined"))
                            })?)
                        }
                        Token::Text(bytes) => {
                            let next = terminals.len();
                            Symbol::Terminal(*terminal_index.entry(bytes.clone()).or_insert_with(
                                || {
                                    terminals.push(bytes.clone());
                                    next
                                },
                            ))
                        }
                        Token::Equals | Token::Bar | Token::Semicolon => {
                            return Err(invalid(format!("line {line}: unexpected punctuation")));
                        }
                    });
                }
                symbols += out.len();
                rule.push(out);
            }
            alternatives += rule.len();
            rules.push(rule);
        }
        if alternatives > MAX_ALTERNATIVES {
            return Err(invalid(format!(
                "more than {MAX_ALTERNATIVES} alternatives"
            )));
        }
        if symbols > MAX_SYMBOLS {
            return Err(invalid(format!("more than {MAX_SYMBOLS} symbols")));
        }
        if terminals.len() > MAX_TERMINALS {
            return Err(invalid(format!(
                "more than {MAX_TERMINALS} distinct terminals"
            )));
        }
        if terminals.iter().map(Vec::len).sum::<usize>() > MAX_TERMINAL_BYTES {
            return Err(invalid("terminals exceed 16 KiB in total"));
        }
        let names: Vec<String> = parsed.into_iter().map(|(name, _, _)| name).collect();
        let shortest = shortest_alternatives(&names, &rules)?;
        Ok(Self {
            names,
            rules,
            terminals,
            shortest,
        })
    }
}

fn tokenize(text: &str) -> Result<Vec<(Token, usize)>, ClassifiedError> {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let (mut i, mut line) = (0_usize, 1_usize);
    while i < bytes.len() {
        match bytes[i] {
            b'\n' => {
                line += 1;
                i += 1;
            }
            b' ' | b'\t' | b'\r' => i += 1,
            b'#' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'=' => {
                tokens.push((Token::Equals, line));
                i += 1;
            }
            b'|' => {
                tokens.push((Token::Bar, line));
                i += 1;
            }
            b';' => {
                tokens.push((Token::Semicolon, line));
                i += 1;
            }
            b'"' => {
                let (value, next) = scan_terminal(bytes, i + 1, line)?;
                tokens.push((Token::Text(value), line));
                i = next;
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                // The slice holds only ASCII identifier bytes.
                tokens.push((
                    Token::Name(String::from_utf8_lossy(&bytes[start..i]).into_owned()),
                    line,
                ));
            }
            _ => {
                return Err(invalid(format!(
                    "line {line}: unexpected character; quote literal text"
                )))
            }
        }
    }
    Ok(tokens)
}

fn scan_terminal(
    bytes: &[u8],
    mut i: usize,
    line: usize,
) -> Result<(Vec<u8>, usize), ClassifiedError> {
    let bad = || invalid(format!("line {line}: unsupported escape in a terminal"));
    let mut out = Vec::new();
    loop {
        match bytes.get(i) {
            None | Some(b'\n') => {
                return Err(invalid(format!("line {line}: unterminated terminal")));
            }
            Some(b'"') => return Ok((out, i + 1)),
            Some(b'\\') => {
                let escape = *bytes.get(i + 1).ok_or_else(bad)?;
                i += 2;
                out.push(match escape {
                    b'\\' => b'\\',
                    b'"' => b'"',
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'0' => 0,
                    b'x' => {
                        let digits = bytes.get(i..i + 2).ok_or_else(bad)?;
                        let text = std::str::from_utf8(digits).map_err(|_| bad())?;
                        i += 2;
                        u8::from_str_radix(text, 16).map_err(|_| bad())?
                    }
                    _ => return Err(bad()),
                });
            }
            Some(byte) => {
                out.push(*byte);
                i += 1;
            }
        }
    }
}

type ParsedRule = (String, usize, Vec<Vec<Token>>);

fn parse_rules(tokens: &[(Token, usize)]) -> Result<Vec<ParsedRule>, ClassifiedError> {
    let mut rules = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let (Token::Name(name), line) = &tokens[i] else {
            return Err(invalid(format!(
                "line {}: expected a rule name",
                tokens[i].1
            )));
        };
        if !matches!(tokens.get(i + 1), Some((Token::Equals, _))) {
            return Err(invalid(format!("line {line}: expected '=' after '{name}'")));
        }
        i += 2;
        let mut alternatives = vec![Vec::new()];
        loop {
            match tokens.get(i) {
                None => {
                    return Err(invalid(format!(
                        "line {line}: rule '{name}' has no closing ';'"
                    )));
                }
                Some((Token::Semicolon, _)) => {
                    i += 1;
                    break;
                }
                Some((Token::Bar, _)) => alternatives.push(Vec::new()),
                Some((Token::Equals, at)) => {
                    return Err(invalid(format!(
                        "line {at}: unexpected '='; is a ';' missing?"
                    )));
                }
                Some((symbol, _)) => {
                    if let Some(current) = alternatives.last_mut() {
                        current.push(symbol.clone());
                    }
                }
            }
            i += 1;
        }
        rules.push((name.clone(), *line, alternatives));
    }
    Ok(rules)
}

/// For each rule, the alternative that terminates in the fewest nested
/// expansions. A rule with no terminating alternative is an error: the
/// generated expander could not bound it.
fn shortest_alternatives(
    names: &[String],
    rules: &[Vec<Vec<Symbol>>],
) -> Result<Vec<usize>, ClassifiedError> {
    let mut depth: Vec<Option<usize>> = vec![None; rules.len()];
    let mut shortest = vec![0_usize; rules.len()];
    let mut changed = true;
    while changed {
        changed = false;
        for (rule, alternatives) in rules.iter().enumerate() {
            for (position, alternative) in alternatives.iter().enumerate() {
                let nested = alternative.iter().try_fold(0_usize, |deepest, symbol| {
                    Some(match symbol {
                        Symbol::Terminal(_) => deepest,
                        Symbol::Rule(inner) => deepest.max(depth[*inner]?),
                    })
                });
                let Some(nested) = nested else { continue };
                if depth[rule].is_none_or(|known| nested + 1 < known) {
                    depth[rule] = Some(nested + 1);
                    shortest[rule] = position;
                    changed = true;
                }
            }
        }
    }
    if let Some(rule) = depth.iter().position(Option::is_none) {
        return Err(invalid(format!(
            "rule '{}' can never terminate: every alternative leads back into a rule \
             without a terminating alternative",
            names[rule]
        )));
    }
    Ok(shortest)
}

fn write_numbers(out: &mut String, values: impl Iterator<Item = String>) {
    let mut column = 0;
    let mut any = false;
    for value in values {
        any = true;
        if column + value.len() + 1 > 96 {
            out.push('\n');
            column = 0;
        }
        out.push_str(&value);
        out.push(',');
        column += value.len() + 1;
    }
    if !any {
        // C forbids an empty array.
        out.push_str("0,");
    }
}

/// Generate the native mutator source for `engine` from `grammar`.
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] when the `managed-mutators`
/// feature is disabled, for an engine without a native custom-mutator
/// interface, or for a grammar whose tables exceed the source allowance.
pub fn generate(grammar: &Grammar, engine: EngineKind) -> Result<String, ClassifiedError> {
    if !cfg!(feature = "managed-mutators") {
        return Err(invalid("managed-mutators feature is disabled"));
    }
    if !matches!(engine, EngineKind::AflPlusPlus | EngineKind::LibFuzzer) {
        return Err(invalid(
            "only AFL++ and libFuzzer have a native custom mutator interface",
        ));
    }
    let mut out = String::new();
    let _ = write!(
        out,
        "/* Grammar mutator generated by oxfuzz: {} rule(s), start rule '{}'.\n   \
         Generated source is reviewed and qualified like hand-written source. */\n\
         #include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n\
         #ifdef __cplusplus\nextern \"C\" {{\n#endif\n\
         #define GM_CAP 65536u\n#define GM_FRAG 4096u\n#define GM_DEPTH 24u\n\
         #define GM_STEPS 20000L\n#define GM_TERMS {}u\n#define GM_RULES {}u\n\
         typedef struct {{ uint16_t first; uint16_t count; }} gm_span;\n",
        grammar.rules.len(),
        grammar.names[0].replace("*/", ""),
        grammar.terminals.len(),
        grammar.rules.len(),
    );

    out.push_str("static const unsigned char gm_bytes[] = {\n");
    write_numbers(
        &mut out,
        grammar.terminals.iter().flatten().map(u8::to_string),
    );
    out.push_str("\n};\nstatic const gm_span gm_terms[] = {\n");
    let mut offset = 0_usize;
    write_numbers(
        &mut out,
        grammar.terminals.iter().map(|terminal| {
            let span = format!("{{{offset},{}}}", terminal.len());
            offset += terminal.len();
            span
        }),
    );
    out.push_str("\n};\nstatic const uint16_t gm_syms[] = {\n");
    let terminal_count = grammar.terminals.len();
    write_numbers(
        &mut out,
        grammar.rules.iter().flatten().flatten().map(|symbol| {
            match symbol {
                Symbol::Terminal(index) => *index,
                Symbol::Rule(index) => terminal_count + index,
            }
            .to_string()
        }),
    );
    out.push_str("\n};\nstatic const gm_span gm_alts[] = {\n");
    let mut symbol_offset = 0_usize;
    write_numbers(
        &mut out,
        grammar.rules.iter().flatten().map(|alternative| {
            let span = format!("{{{symbol_offset},{}}}", alternative.len());
            symbol_offset += alternative.len();
            span
        }),
    );
    out.push_str("\n};\nstatic const gm_span gm_rules[] = {\n");
    let mut alternative_offset = 0_usize;
    let mut first_alternative = Vec::with_capacity(grammar.rules.len());
    write_numbers(
        &mut out,
        grammar.rules.iter().map(|rule| {
            let span = format!("{{{alternative_offset},{}}}", rule.len());
            first_alternative.push(alternative_offset);
            alternative_offset += rule.len();
            span
        }),
    );
    out.push_str("\n};\nstatic const uint16_t gm_short[] = {\n");
    write_numbers(
        &mut out,
        grammar
            .shortest
            .iter()
            .zip(&first_alternative)
            .map(|(shortest, first)| (first + shortest).to_string()),
    );
    out.push_str("\n};\n");
    out.push_str(EXPANDER);
    out.push_str(if engine == EngineKind::AflPlusPlus {
        AFL_CALLBACKS
    } else {
        LIBFUZZER_CALLBACKS
    });
    out.push_str("#ifdef __cplusplus\n}\n#endif\n");
    if out.len() > MAX_GENERATED_BYTES {
        return Err(invalid(
            "the grammar is too large: its generated source exceeds 40 KiB",
        ));
    }
    Ok(out)
}

/// The table interpreter. Budgets bound every call: past `GM_DEPTH` nested
/// expansions or `GM_STEPS` expansions in total, each rule takes its
/// shortest alternative, and past twice the step budget expansion stops.
const EXPANDER: &str = r"static unsigned char gm_buf[GM_CAP];
static unsigned char gm_frag[GM_FRAG];
static uint32_t gm_state = 0x9e3779b9u;
static long gm_steps;

static uint32_t gm_next(void) {
  uint32_t x = gm_state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  if (x == 0) x = 0x9e3779b9u;
  gm_state = x;
  return x;
}

static size_t gm_emit(unsigned rule, unsigned depth, unsigned char *out, size_t len, size_t cap) {
  gm_span r = gm_rules[rule];
  gm_span a;
  unsigned i;
  if (--gm_steps < -GM_STEPS) return len;
  a = gm_alts[(depth >= GM_DEPTH || gm_steps < 0) ? gm_short[rule] : r.first + gm_next() % r.count];
  for (i = 0; i < a.count && len < cap; i++) {
    unsigned sym = gm_syms[a.first + i];
    if (sym < GM_TERMS) {
      gm_span t = gm_terms[sym];
      size_t n = t.count;
      if (n > cap - len) n = cap - len;
      if (n) memcpy(out + len, gm_bytes + t.first, n);
      len += n;
    } else {
      len = gm_emit(sym - GM_TERMS, depth + 1, out, len, cap);
    }
  }
  return len;
}

/* Write a mutated input into gm_buf: a fresh sentence, or the current input
   with a generated fragment inserted or put in place of a span. */
static size_t gm_mutate(const unsigned char *data, size_t size, size_t max_size) {
  size_t cap = max_size < GM_CAP ? max_size : GM_CAP;
  size_t n, pos, del, tail;
  uint32_t choice = gm_next() & 3u;
  if (cap == 0) return 0;
  if (size > cap) size = cap;
  gm_steps = GM_STEPS;
  if (size == 0 || choice == 0) {
    n = gm_emit(0, 0, gm_buf, 0, cap);
    if (n) return n;
    if (size) memcpy(gm_buf, data, size);
    return size;
  }
  n = gm_emit(gm_next() % GM_RULES, GM_DEPTH / 2u, gm_frag, 0, GM_FRAG);
  pos = gm_next() % (size + 1u);
  del = 0;
  if (choice != 1u && pos < size) del = 1u + gm_next() % (size - pos);
  if (del > n + 16u) del = n + 16u;
  if (pos) memcpy(gm_buf, data, pos);
  if (n > cap - pos) n = cap - pos;
  if (n) memcpy(gm_buf + pos, gm_frag, n);
  tail = size - pos - del;
  if (tail > cap - pos - n) tail = cap - pos - n;
  if (tail) memcpy(gm_buf + pos + n, data + pos + del, tail);
  return pos + n + tail;
}

";

/// libFuzzer calls only the custom mutator once one is defined, so a share
/// of calls is handed back to its byte-level mutator.
const LIBFUZZER_CALLBACKS: &str = r"size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size, unsigned int seed) {
  size_t n;
  gm_state = seed ? seed : 0x9e3779b9u;
  if (size && (gm_next() & 3u) == 0) return LLVMFuzzerMutate(data, size, max_size);
  n = gm_mutate(data, size, max_size);
  if (n) memcpy(data, gm_buf, n);
  return n;
}
";

const AFL_CALLBACKS: &str = r"void *afl_custom_init(void *afl, unsigned int seed) {
  (void)afl;
  gm_state = seed ? seed : 0x9e3779b9u;
  return &gm_state;
}

size_t afl_custom_fuzz(void *state, unsigned char *buf, size_t buf_size, unsigned char **out_buf,
                       unsigned char *add_buf, size_t add_buf_size, size_t max_size) {
  (void)state;
  (void)add_buf;
  (void)add_buf_size;
  *out_buf = gm_buf;
  return gm_mutate(buf, buf_size, max_size);
}

void afl_custom_deinit(void *state) { (void)state; }
";

#[cfg(all(test, feature = "managed-mutators"))]
mod tests {
    use super::*;
    use hf_core::target::TargetLanguage;

    const JSON: &str = "# a small JSON subset\n\
        value  = object | array | \"true\" | \"null\" | number ;\n\
        object = \"{\" \"}\" | \"{\" pair \"}\" ;\n\
        pair   = \"\\\"k\\\":\" value ;\n\
        array  = \"[\" \"]\" | \"[\" value \",\" value \"]\" ;\n\
        number = \"0\" | \"-1\" | \"1e9\" | \"\\x30\\n\" ;\n";

    fn error(text: &str) -> String {
        Grammar::parse(text).unwrap_err().to_string()
    }

    #[test]
    fn a_grammar_parses_rules_terminals_and_shortest_alternatives() {
        let grammar = Grammar::parse(JSON).unwrap();
        assert_eq!(grammar.rule_count(), 5);
        assert_eq!(grammar.names[0], "value");
        // `value` terminates soonest through a literal; `object` and `array`
        // through their empty forms; `pair` only through `value`.
        assert_eq!(grammar.shortest, vec![2, 0, 0, 0, 0]);
        assert!(grammar.terminals.contains(&b"\"k\":".to_vec()));
        assert!(grammar.terminals.contains(&b"0\n".to_vec()));
        // A terminal used twice is stored once.
        assert_eq!(
            grammar
                .terminals
                .iter()
                .filter(|terminal| terminal.as_slice() == b"{")
                .count(),
            1
        );
    }

    #[test]
    fn an_empty_alternative_is_allowed_and_terminates() {
        let grammar = Grammar::parse("list = | \"x\" list ;").unwrap();
        assert_eq!(grammar.shortest, vec![0]);
    }

    #[test]
    fn grammar_errors_name_the_line_or_the_rule() {
        assert!(error("a = b ;").contains("line 1: rule 'b' is not defined"));
        assert!(error("a = \"x\" ;\na = \"y\" ;").contains("line 2: rule 'a' is defined twice"));
        assert!(error("a = \"x\" a ;").contains("rule 'a' can never terminate"));
        assert!(error("a = b ;\nb = a ;").contains("can never terminate"));
        assert!(error("a = \"x\"").contains("no closing ';'"));
        assert!(error("a \"x\" ;").contains("expected '=' after 'a'"));
        assert!(error("a = \"x\"\nb = \"y\" ;").contains("is a ';' missing"));
        assert!(error("a = \"x ;").contains("unterminated terminal"));
        assert!(error("a = \"\\q\" ;").contains("unsupported escape"));
        assert!(error("a = x-y ;").contains("unexpected character"));
        assert!(error("# nothing\n").contains("defines no rule"));
        assert!(error("= \"x\" ;").contains("expected a rule name"));
    }

    #[test]
    fn size_limits_are_errors() {
        let mut many = String::new();
        for n in 0..=MAX_RULES {
            let _ = writeln!(many, "r{n} = \"x\" ;");
        }
        assert!(error(&many).contains("more than 256 rules"));
        let big = format!("a = \"{}\" ;", "x".repeat(MAX_TERMINAL_BYTES + 1));
        assert!(error(&big).contains("terminals exceed"));
    }

    #[test]
    fn generation_is_deterministic_and_defines_the_engine_callbacks() {
        let grammar = Grammar::parse(JSON).unwrap();
        let libfuzzer = generate(&grammar, EngineKind::LibFuzzer).unwrap();
        assert_eq!(
            libfuzzer,
            generate(&grammar, EngineKind::LibFuzzer).unwrap()
        );
        assert!(libfuzzer.contains("size_t LLVMFuzzerCustomMutator("));
        assert!(!libfuzzer.contains("afl_custom_"));
        assert!(libfuzzer.contains("#define GM_RULES 5u"));

        let afl = generate(&grammar, EngineKind::AflPlusPlus).unwrap();
        for callback in ["afl_custom_init", "afl_custom_fuzz", "afl_custom_deinit"] {
            assert!(afl.contains(callback), "{callback}");
        }
        assert!(!afl.contains("LLVMFuzzerCustomMutator"));
        // Custom trimming is all three callbacks or none.
        assert!(!afl.contains("afl_custom_trim"));
    }

    #[test]
    fn engines_without_a_native_mutator_interface_are_refused() {
        let grammar = Grammar::parse(JSON).unwrap();
        for engine in [
            EngineKind::Honggfuzz,
            EngineKind::Syzkaller,
            EngineKind::GoNative,
        ] {
            assert!(generate(&grammar, engine).is_err(), "{engine:?}");
        }
    }

    #[test]
    fn the_managed_mutator_envelope_accepts_generated_source() {
        let grammar = Grammar::parse(JSON).unwrap();
        let base = "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) \
                    { (void)d; (void)n; return 0; }";
        for engine in [EngineKind::LibFuzzer, EngineKind::AflPlusPlus] {
            let source = generate(&grammar, engine).unwrap();
            for language in [TargetLanguage::C, TargetLanguage::Cpp] {
                let composed =
                    crate::managed_mutator::compose(base, &source, engine, language).unwrap();
                assert!(crate::managed_mutator::inspect(&composed, engine, language)
                    .unwrap()
                    .is_some());
            }
        }
    }

    #[test]
    fn an_empty_grammar_table_still_compiles_as_c() {
        // A grammar with no terminal and no symbol would emit empty arrays,
        // which C forbids.
        let grammar = Grammar::parse("a = ;").unwrap();
        let source = generate(&grammar, EngineKind::LibFuzzer).unwrap();
        assert!(source.contains("gm_bytes[] = {\n0,\n}"), "{source}");
        assert!(source.contains("gm_syms[] = {\n0,\n}"), "{source}");
    }
}
