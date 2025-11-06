// Copyright 2025 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{borrow::Cow, str::FromStr};

pub use parser::ParseError;

use super::{
    hop_pattern::{lexer::HopPatternLexer, parser::HopPatternParser},
    types::{HopPredicate, PathPolicyHop},
};
use crate::path::policy::PathPolicy;

/// Path Policy Hop pattern
///
/// A hop pattern is a series of expressions that must match in order.
/// Expressions can be combined with operators to form complex patterns.
/// Supported operators:
/// - `|` (OR): Either the left or right expression must match.
/// - `?` (Optional): The preceding expression may appear zero or one time.
/// - `+` (One or more): The preceding expression must appear one or more times.
/// - `*` (Zero or more): The preceding expression may appear zero or more times.
/// - Parentheses `(` and `)` can be used to group expressions and control precedence.
///
/// Examples:
///
/// ```
/// pub use scion_proto::path::policy::hop_pattern::HopPatternPolicy;
///
/// // Requires two hops: first in ISD 1, followed by a hop in ISD 2 with ASN ff00:0:133
/// // and interface 2.
/// HopPatternPolicy::parse("1 2-ff00:0:133#2").unwrap();
///
/// // Requires a path with a single hop, either in ISD 1 ASN 2 or a hop in ISD 2 with ASN ff00:0:133
/// // and interface 2.
/// HopPatternPolicy::parse("1-2 | 2-ff00:0:133#2").unwrap();
///
/// // Requires a path starting with a hop in ISD 1, followed optionally by a hop in ISD 2 or 3, and
/// // ending with one or more hops in ISD 4.
/// HopPatternPolicy::parse("1 (2 | 3)? 4+").unwrap();
///
/// // Requires a path with one or more hops in any ISD (0 is wildcard), followed by one or more hops
/// // in ISD 1 or 2, and one or more hops in ISD 3.
/// HopPatternPolicy::parse("0+ (1 | 2)+ 3+").unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct HopPatternPolicy(Vec<HopPatternExpression>);

impl HopPatternPolicy {
    /// Parses a hop pattern expression from a string.
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        let tokens = HopPatternLexer::new(s).tokenize();
        HopPatternParser::new(&tokens).parse()
    }

    /// Checks if the hop pattern matches the given hops.
    pub fn matches(&self, hops: &[PathPolicyHop]) -> bool {
        // Start at position 0, apply each top-level expression in hop pattern
        let mut positions: Vec<usize> = vec![0];
        for expr in &self.0 {
            let mut next_positions = Vec::new();

            for &position in &positions {
                // Collect all positions reachable from current position by this expression
                next_positions.extend(expr.match_from(hops, position));
            }

            next_positions.sort_unstable();
            next_positions.dedup();
            positions = next_positions;

            if positions.is_empty() {
                return false;
            }
        }

        // Successful if any position reached the end of the hops
        positions.contains(&hops.len())
    }
}
impl FromStr for HopPatternPolicy {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}
impl PathPolicy for HopPatternPolicy {
    fn path_allowed<T>(
        &self,
        path: &crate::path::Path<T>,
    ) -> Result<bool, std::borrow::Cow<'static, str>> {
        let path_hops = PathPolicyHop::hops_from_path(path).map_err(Cow::from)?;
        Ok(self.matches(&path_hops))
    }
}

/// An expression in a path policy hop pattern.
#[derive(Debug, Clone)]
enum HopPatternExpression {
    HopPredicate(HopPredicate),
    Or(Box<HopPatternExpression>, Box<HopPatternExpression>),
    Optional(Box<HopPatternExpression>),
    OneOrMore(Box<HopPatternExpression>),
    ZeroOrMore(Box<HopPatternExpression>),
}
impl HopPatternExpression {
    /// Recursively matches the expression starting from `pos`, returning all valid next positions
    /// after consuming this expression.
    ///
    /// For example, if the expression matches one hop, it returns `vec![pos + 1]`.
    /// If it matches zero hops (e.g. an optional expression), it returns `vec![pos]`.
    /// If it can match multiple ways, it returns all resulting positions.
    pub fn match_from(&self, hops: &[PathPolicyHop], pos: usize) -> Vec<usize> {
        let mut valid_next_positions = match self {
            HopPatternExpression::HopPredicate(pred) => {
                if pos < hops.len() && hops[pos].matches(pred) {
                    vec![pos + 1] // Consumes one hop
                } else {
                    vec![]
                }
            }

            HopPatternExpression::Or(a, b) => {
                // union of both branch results
                let mut left = a.match_from(hops, pos);
                let mut right = b.match_from(hops, pos);
                left.append(&mut right);
                left
            }

            HopPatternExpression::Optional(inner) => {
                // either skip or take one inner match
                let mut res = vec![pos];
                res.extend(inner.match_from(hops, pos));
                res
            }

            HopPatternExpression::OneOrMore(inner) => {
                // must match once, then repeat while possible
                Self::all_nested_matches(hops, pos, inner)
            }

            HopPatternExpression::ZeroOrMore(inner) => {
                // allow zero matches plus as many repeats as possible
                let mut vec = Self::all_nested_matches(hops, pos, inner);
                vec.push(pos);
                vec
            }
        };

        valid_next_positions.sort_unstable();
        valid_next_positions.dedup();
        valid_next_positions
    }

    /// Recursively matches the inner expression starting from `pos`, collecting all reachable
    /// positions
    fn all_nested_matches(
        hops: &[PathPolicyHop],
        pos: usize,
        inner: &HopPatternExpression,
    ) -> Vec<usize> {
        let mut all = Vec::new();
        let mut frontier = inner.match_from(hops, pos);
        all.extend(&frontier);

        while !frontier.is_empty() {
            let mut next = Vec::new();
            for p in frontier {
                let res = inner.match_from(hops, p);
                for n in res {
                    if !all.contains(&n) {
                        all.push(n);
                        next.push(n);
                    }
                }
            }
            frontier = next;
        }

        all.sort_unstable();
        all.dedup();
        all
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::IsdAsn;

    // Helper to build a hop vector easily.
    // Each tuple: (isd_asn_str, ingress, egress)
    fn hops(spec: &[&str]) -> Vec<PathPolicyHop> {
        spec.iter()
            .map(|s| {
                PathPolicyHop {
                    isd_asn: IsdAsn::from_str(s).expect("valid IsdAsn"),
                    ingress: 0,
                    egress: 0,
                }
            })
            .collect()
    }

    mod happy {
        use super::*;

        // Simple
        //
        #[test]
        fn should_match_simple_linear_hop_pattern() {
            let seq = HopPatternPolicy::parse("1 2 3").unwrap();
            let hv = hops(&["1-1", "2-1", "3-1"]);
            assert!(seq.matches(&hv));
        }

        #[test]
        fn should_not_match_when_path_too_short() {
            let seq = HopPatternPolicy::parse("1 2 3").unwrap();
            let hv = hops(&["1-1", "2-1"]);
            assert!(!seq.matches(&hv));
        }

        #[test]
        fn should_not_match_wrong_order() {
            let seq = HopPatternPolicy::parse("1 2").unwrap();
            let hv = hops(&["2-1", "1-1"]);
            assert!(!seq.matches(&hv));
        }

        // Optionals
        //
        #[test]
        fn should_match_with_optional_absent() {
            let seq = HopPatternPolicy::parse("1 2? 3").unwrap();
            let hv = hops(&["1-1", "3-1"]);
            assert!(seq.matches(&hv));
        }

        #[test]
        fn should_match_with_optional_present() {
            let seq = HopPatternPolicy::parse("1 2? 3").unwrap();
            let hv = hops(&["1-1", "2-1", "3-1"]);
            assert!(seq.matches(&hv));
        }

        // One Or More
        //
        #[test]
        fn should_match_one_or_more_single() {
            let seq = HopPatternPolicy::parse("1+").unwrap();
            let hv = hops(&["1-1"]);
            assert!(seq.matches(&hv));
        }

        #[test]
        fn should_match_one_or_more_multiple() {
            let seq = HopPatternPolicy::parse("1+").unwrap();
            let hv = hops(&["1-1", "1-1", "1-1"]);
            assert!(seq.matches(&hv));
        }
        #[test]
        fn should_match_one_or_more_multiple_with_final_segment() {
            let seq = HopPatternPolicy::parse("1+ 1-4").unwrap();
            let hv = hops(&["1-1", "1-1", "1-1", "1-4"]);
            assert!(seq.matches(&hv));
        }

        #[test]
        fn should_not_match_one_or_more_multiple_with_missing_final_segment() {
            let seq = HopPatternPolicy::parse("1+ 1-4").unwrap();
            let hv = hops(&["1-1", "1-1", "1-1", "1-5"]);
            assert!(!seq.matches(&hv));
        }

        #[test]
        fn should_not_match_one_or_more_with_zero() {
            let seq = HopPatternPolicy::parse("1+").unwrap();
            let hv = hops(&["2-1"]);
            assert!(!seq.matches(&hv));
        }

        // Zero Or More
        //
        #[test]
        fn should_match_zero_or_more_zero_case() {
            let seq = HopPatternPolicy::parse("1* 2").unwrap();
            let hv = hops(&["2-1"]);
            assert!(seq.matches(&hv));
        }

        #[test]
        fn should_match_zero_or_more_multiple_case() {
            let seq = HopPatternPolicy::parse("1* 2").unwrap();
            let hv = hops(&["1-1", "1-1", "2-1"]);
            assert!(seq.matches(&hv));
        }

        #[test]
        fn should_match_zero_or_more_with_final() {
            let seq = HopPatternPolicy::parse("1* 1-5").unwrap();
            let hv = hops(&["1-1", "1-1", "1-5"]);
            assert!(seq.matches(&hv));
        }

        #[test]
        fn should_not_match_zero_or_more_with_bad_final() {
            let seq = HopPatternPolicy::parse("1* 1-5").unwrap();
            let hv = hops(&["1-1", "1-1", "1-4"]);
            assert!(!seq.matches(&hv));
        }

        // OR Branches
        //

        #[test]
        fn should_match_or_left_branch() {
            let seq = HopPatternPolicy::parse("(1 | 2) 3").unwrap();
            let hv = hops(&["1-1", "3-1"]);
            assert!(seq.matches(&hv));
        }

        #[test]
        fn should_match_or_right_branch() {
            let seq = HopPatternPolicy::parse("(1 | 2) 3").unwrap();
            let hv = hops(&["2-1", "3-1"]);
            assert!(seq.matches(&hv));
        }

        #[test]
        fn should_match_chained_or_middle() {
            let seq = HopPatternPolicy::parse("1 | 2 | 3").unwrap();
            let hv = hops(&["2-1"]);
            assert!(seq.matches(&hv));
        }

        #[test]
        fn should_not_match_or_when_no_branch_matches() {
            let seq = HopPatternPolicy::parse("(1 | 2) 3").unwrap();
            let hv = hops(&["4-1", "3-1"]);
            assert!(!seq.matches(&hv));
        }

        #[test]
        fn should_match_concatenated_alternations() {
            let seq = HopPatternPolicy::parse("(1 | 2) (3 | 4)").unwrap();
            let hv = hops(&["2-1", "4-1"]);
            assert!(seq.matches(&hv));
        }

        /// Complex

        #[test]
        fn should_handle_complex_nested_quantifiers_and_or() {
            let seq = HopPatternPolicy::parse("1 (2+ | 3) 4").unwrap();
            let hv = hops(&["1-1", "2-1", "2-1", "4-1"]);
            assert!(seq.matches(&hv));

            let hv = hops(&["1-1", "3-1", "4-1"]);
            assert!(seq.matches(&hv));

            // Can only go through 2 or 3, not both
            let hv = hops(&["1-1", "2-1", "2-1", "3-1", "4-1"]);
            assert!(!seq.matches(&hv));

            // Missing either
            let hv = hops(&["1-1", "4-1"]);
            assert!(!seq.matches(&hv));
        }

        #[test]
        fn should_match_optional_followed_by_plus() {
            let seq = HopPatternPolicy::parse("1? 2+ 3").unwrap();
            let hv = hops(&["2-1", "3-1"]);
            assert!(seq.matches(&hv));
        }

        #[test]
        fn should_match_zero_or_more_then_plus() {
            let seq = HopPatternPolicy::parse("1* 2+").unwrap();
            let hv = hops(&["1-1", "1-1", "2-1", "2-1"]);
            assert!(seq.matches(&hv));
        }

        // Random tests
        //

        #[test]
        fn should_not_match_plus_group_missing_required_repetition() {
            let seq = HopPatternPolicy::parse("0+ (1 | 2)+ 3+").unwrap();
            let hv = hops(&["0-1", "1-1", "2-1"]);
            assert!(!seq.matches(&hv));
        }

        #[test]
        fn should_not_match_optional_path_still_fails_later() {
            let seq = HopPatternPolicy::parse("1? 2 3").unwrap();
            let hv = hops(&["1-1", "2-1"]); // missing 3
            assert!(!seq.matches(&hv));
        }

        #[test]
        fn should_not_match_star_consumes_all_and_misses_tail() {
            let seq = HopPatternPolicy::parse("1* 2 3").unwrap();
            let hv = hops(&["1-1", "1-1", "2-1"]); // missing 3
            assert!(!seq.matches(&hv));
        }

        #[test]
        fn should_not_match_concatenated_alternations_wrong_second() {
            let seq = HopPatternPolicy::parse("(1 | 2) (3 | 4)").unwrap();
            let hv = hops(&["2-1", "5-1"]);
            assert!(!seq.matches(&hv));
        }
    }
}

/// Lexer for path policy hop patterns
pub mod lexer {
    /// The different kinds of tokens that can appear in a hop pattern expression.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum TokenKind {
        /// A hop predicate, e.g. "1-ff00:0:133#1"
        HopPredicate(String),
        /// '!' (negation)
        Bang,
        /// '&' (and)
        And,
        /// '|' (or)
        Or,
        /// '(' (left parenthesis)
        LParen,
        /// ')' (right parenthesis)
        RParen,
        /// '?' (optional quantifier)
        QMark,
        /// '+' (one or more quantifier)
        Plus,
        /// '*' (zero or more quantifier)
        Star,
        /// End of input
        EOI,
    }

    /// A token with its kind and the span (start, end) in the input string.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Token {
        /// The kind of token.
        pub kind: TokenKind,
        /// The span (start, end) of the token in the input string.
        pub span: (usize, usize),
    }

    /// Helper type for returning a reference to a token and its kind.
    pub type TokenSplat<'t> = (TokenKind, (usize, usize));

    impl Token {
        /// Returns a tuple of (&TokenKind, &Token) for convenience.
        pub fn splat(&self) -> TokenSplat<'_> {
            (self.kind.clone(), self.span)
        }

        /// Creates a simple token with a single-character span.
        #[inline]
        fn single_char(kind: TokenKind, i: usize) -> Self {
            Self {
                kind,
                span: (i, i + 1),
            }
        }
    }
    /// Lexer for hop pattern expressions. Produces tokens from an input string.
    pub struct HopPatternLexer<'a> {
        /// Peekable iterator over the input string's character indices.
        input: std::iter::Peekable<std::str::CharIndices<'a>>,
        /// Length of the input string.
        len: usize,
    }

    impl<'a> HopPatternLexer<'a> {
        /// Characters reserved as operators or delimiters.
        const RESERVED_CHARS: &'static str = "!&|()+?*";

        /// Create a new lexer for the given input string.
        pub fn new(s: &'a str) -> Self {
            Self {
                input: s.char_indices().peekable(),
                len: s.len(),
            }
        }

        /// Returns the next token from the input, or None if finished.
        fn next_token(&mut self) -> Option<Token> {
            while let Some((idx, c)) = self.input.next() {
                return Some(match c {
                    '?' => Token::single_char(TokenKind::QMark, idx),
                    '+' => Token::single_char(TokenKind::Plus, idx),
                    '*' => Token::single_char(TokenKind::Star, idx),
                    '!' => Token::single_char(TokenKind::Bang, idx),
                    '&' => Token::single_char(TokenKind::And, idx),
                    '|' => Token::single_char(TokenKind::Or, idx),
                    '(' => Token::single_char(TokenKind::LParen, idx),
                    ')' => Token::single_char(TokenKind::RParen, idx),
                    ' ' | '\t' | '\n' => continue, // skip whitespace
                    _ => self.read_hop_predicate(c, idx),
                });
            }
            None
        }

        /// Reads a hop predicate token starting with the given character.
        fn read_hop_predicate(&mut self, first_char: char, start: usize) -> Token {
            let mut ident = String::new();
            ident.push(first_char);
            while let Some((_, p)) = self.input.peek().copied() {
                if p.is_whitespace() || Self::RESERVED_CHARS.contains(p) {
                    break;
                }
                self.input.next();
                ident.push(p);
            }
            let end = start + ident.len();
            Token {
                kind: TokenKind::HopPredicate(ident),
                span: (start, end),
            }
        }

        /// Tokenizes the entire input and returns a vector of tokens, ending with EOI.
        pub fn tokenize(&mut self) -> Vec<Token> {
            let mut out = Vec::new();
            while let Some(t) = self.next_token() {
                out.push(t);
            }
            out.push(Token {
                kind: TokenKind::EOI,
                span: (self.len, self.len),
            });

            out
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::path::policy::hop_pattern::lexer::{HopPatternLexer, TokenKind};

        #[test]
        fn test_single_ident() {
            let mut lx = HopPatternLexer::new("1-ff00:0:133#1");
            let tokens = lx.tokenize();
            assert_eq!(tokens.len(), 2);
            assert_eq!(
                tokens[0].kind,
                TokenKind::HopPredicate("1-ff00:0:133#1".into())
            );
            assert_eq!(tokens[1].kind, TokenKind::EOI);
        }

        #[test]
        fn test_symbols() {
            let mut lx = HopPatternLexer::new("! & | ( ) ? + *");
            let tokens = lx.tokenize();
            let kinds: Vec<_> = tokens.into_iter().map(|t| t.kind).collect();
            assert_eq!(
                kinds,
                vec![
                    TokenKind::Bang,
                    TokenKind::And,
                    TokenKind::Or,
                    TokenKind::LParen,
                    TokenKind::RParen,
                    TokenKind::QMark,
                    TokenKind::Plus,
                    TokenKind::Star,
                    TokenKind::EOI,
                ]
            );
        }

        #[test]
        fn test_expression_mixed() {
            let mut lx = HopPatternLexer::new("!foo & (bar | baz)");
            let tokens = lx.tokenize();
            let kinds: Vec<_> = tokens.into_iter().map(|t| t.kind).collect();
            assert_eq!(
                kinds,
                vec![
                    TokenKind::Bang,
                    TokenKind::HopPredicate("foo".into()),
                    TokenKind::And,
                    TokenKind::LParen,
                    TokenKind::HopPredicate("bar".into()),
                    TokenKind::Or,
                    TokenKind::HopPredicate("baz".into()),
                    TokenKind::RParen,
                    TokenKind::EOI,
                ]
            );
        }

        #[test]
        fn test_whitespace_handling() {
            let mut lx = HopPatternLexer::new("  foo\t\n&bar ");
            let tokens = lx.tokenize();
            let kinds: Vec<_> = tokens.into_iter().map(|t| t.kind).collect();
            assert_eq!(
                kinds,
                vec![
                    TokenKind::HopPredicate("foo".into()),
                    TokenKind::And,
                    TokenKind::HopPredicate("bar".into()),
                    TokenKind::EOI,
                ]
            );
        }
    }
}

/// Parser for path policy hop patterns
pub mod parser {

    // Pratt parser.
    // 1. Find the first Expression (Prefix or Atom)
    // 2. Parse Prefixes
    // 3. Parse Infixes (things with left/right association)
    // 4. Decide if the next Infix is part of left hand side
    //   - If Infix Bind Power is lower than current Bind Power => Infix is part of Left hand side
    //
    // - OR      = 11 (+1 Because currently consuming)
    // - 2nd OR  = 10 - Gets parsed into current Left Hand Side
    // - AND     = 20 - Stops parsing Left Hand Side, starts Right Hand Side

    use std::borrow::Cow;

    use super::*;
    use crate::path::policy::hop_pattern::lexer::{Token, TokenKind, TokenSplat};

    /// Precedence for top level objects without left/right hand side (lowest power).
    const NO_BIND_POWER: u8 = 0;
    /// Precedence for logical OR (lower than AND). Larger number = tighter binding.
    const OR_BIND_POWER: u8 = 10;

    /// Defines associativity (grouping direction) for infix operators.
    #[derive(Debug, Clone, Copy)]
    enum Grouping {
        /// Left Associative: a OP b OP c == (a OP b) OP c
        LeftToRight,
        /// Right Associative: a OP b OP c == a OP (b OP c)
        #[allow(dead_code)]
        RightToLeft,
    }

    /// Error returned by the Pratt parser.
    #[derive(Debug, PartialEq)]
    pub struct ParseError {
        /// The span (start, end) in the input string where the error occurred.
        pub span: (usize, usize),
        /// A human-readable error message.
        pub message: Cow<'static, str>,
    }
    impl ParseError {
        /// Creates a new ParseError with the given span and message.
        pub fn new(span: (usize, usize), message: Cow<'static, str>) -> Self {
            Self { span, message }
        }

        /// Pretty formatting of the error with context from the input string.
        ///
        /// `input` must be the original parser input string.
        pub fn report(&self, input: &'static str) -> String {
            let (start, end) = self.span;

            // Clamp span to input length
            let start = start.min(input.len());
            let end = end.min(input.len());

            // Context window around the error
            let context = 20;
            let slice_start = start.saturating_sub(context);
            let slice_end = (end + context).min(input.len());

            let snippet = &input[slice_start..slice_end];

            // Build marker line (at least one ^)
            let marker_offset = start - slice_start;
            let marker_len = (end - start).max(1);

            let mut marker = String::new();
            marker.push_str(&" ".repeat(marker_offset));
            marker.push_str(&"^".repeat(marker_len));

            format!("{snippet}\n{marker}\n{}", self.message)
        }
    }

    /// The parser for path policy hop patterns.
    pub struct HopPatternParser<'a> {
        tokens: &'a [Token],
        pos: usize,
    }

    impl<'a> HopPatternParser<'a> {
        /// Create a new parser for the given tokens.
        pub fn new(tokens: &'a [Token]) -> Self {
            Self { tokens, pos: 0 }
        }

        /// Peek current token kind without consuming.
        fn peek_kind(&self) -> Option<&TokenKind> {
            self.tokens.get(self.pos).map(|t| &t.kind)
        }

        /// Consume current token and advance.
        fn consume(&mut self) -> Option<TokenSplat<'_>> {
            if let Some(t) = self.tokens.get(self.pos) {
                self.pos += 1;
                Some(t.splat())
            } else {
                None
            }
        }

        /// Core expression parser.
        fn parse_expr(
            &mut self,
            left_binding_power: u8,
        ) -> Result<HopPatternExpression, ParseError> {
            // Consume Prefixes / Atoms
            let mut expr = match self.consume() {
                // Atom: HopPredicate
                Some((TokenKind::HopPredicate(s), span)) => {
                    HopPatternExpression::HopPredicate(s.parse().map_err(|e| {
                        ParseError::new(span, format!("invalid hop predicate '{s}': {e}").into())
                    })?)
                }
                // Unsupported prefix operator '!'
                Some((TokenKind::Bang, span)) => {
                    return Err(ParseError::new(
                        span,
                        "Negative lookahead '!' is not supported".into(),
                    ));
                }
                // Parenthesized sub-expression
                Some((TokenKind::LParen, span_l)) => {
                    let nested_expr = self.parse_expr(NO_BIND_POWER)?;
                    match self.consume() {
                        Some((TokenKind::RParen, _)) => nested_expr,
                        Some((_, span)) => {
                            return Err(ParseError::new(span, "expected ')'".into()));
                        }
                        None => {
                            return Err(ParseError::new(
                                span_l,
                                "unexpected end of token stream".into(),
                            ));
                        }
                    }
                }
                // Any other token at expression start is invalid
                Some((kind, span)) => {
                    return Err(ParseError::new(
                        span,
                        format!("unexpected token: {kind:?}, Expected a HopPredicate, '!' or '('")
                            .into(),
                    ));
                }
                // Reached end unexpectedly
                None => {
                    let span = self
                        .tokens
                        .last()
                        .map(|t| (t.span.1, t.span.1))
                        .unwrap_or((0, 0));
                    return Err(ParseError::new(
                        span,
                        "unexpected end of token stream, Expected a HopPredicate, '!' or '('"
                            .into(),
                    ));
                }
            };

            // Left Denotation Loop (consume Infix / Postfix)
            loop {
                // Consume Postfixes Greedily
                match self.peek_kind() {
                    Some(TokenKind::QMark) => {
                        self.consume();
                        expr = HopPatternExpression::Optional(Box::new(expr));
                        continue;
                    }
                    Some(TokenKind::Plus) => {
                        self.consume();
                        expr = HopPatternExpression::OneOrMore(Box::new(expr));
                        continue;
                    }
                    Some(TokenKind::Star) => {
                        self.consume();
                        expr = HopPatternExpression::ZeroOrMore(Box::new(expr));
                        continue;
                    }
                    _ => {}
                }

                // Check for Infix operator
                let (op_binding_power, op_grouping, build_infix): (
                    u8,
                    Grouping,
                    fn(HopPatternExpression, HopPatternExpression) -> HopPatternExpression,
                ) = match self.peek_kind() {
                    // Unsupported infix AND
                    Some(TokenKind::And) => {
                        return Err(ParseError::new(
                            self.tokens[self.pos].span,
                            "AND operator '&' is not supported".into(),
                        ));
                    }
                    Some(TokenKind::Or) => {
                        (OR_BIND_POWER, Grouping::LeftToRight, |lhse, rhse| {
                            HopPatternExpression::Or(Box::new(lhse), Box::new(rhse))
                        })
                    }
                    // No infix => expression complete
                    _ => break,
                };

                // If current binding power is higher than the operator's, start right hand side
                // parsing
                if left_binding_power > op_binding_power {
                    break;
                }

                // Consume operator token
                self.consume();

                // Adjust RHS binding power for associativity
                let rhs_binding_power = match op_grouping {
                    Grouping::LeftToRight => op_binding_power + 1,
                    Grouping::RightToLeft => op_binding_power,
                };

                // Parse RHS and build combined node
                let right_expr = self.parse_expr(rhs_binding_power)?;
                expr = build_infix(expr, right_expr);
            }

            Ok(expr)
        }

        /// Parse a Path Policy Hop Pattern
        ///
        /// Returns a [HopPatternPolicy] on success, or a ParseError on failure.
        pub fn parse(&mut self) -> Result<HopPatternPolicy, ParseError> {
            let mut hop_pattern = Vec::new();
            while self.peek_kind() != Some(&TokenKind::EOI) {
                let expr = self.parse_expr(NO_BIND_POWER)?;
                hop_pattern.push(expr);
            }

            if self.pos < self.tokens.len() - 1 {
                let span = self.tokens[self.pos].span;
                return Err(ParseError::new(span, "unexpected trailing tokens".into()));
            }

            Ok(HopPatternPolicy(hop_pattern))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::address::Isd;

        fn tok(kind: TokenKind) -> Token {
            Token { kind, span: (0, 0) }
        }

        fn parse_single_expression(tokens: Vec<TokenKind>) -> HopPatternExpression {
            let tokens: Vec<Token> = tokens
                .into_iter()
                .map(tok)
                .chain([tok(TokenKind::EOI)])
                .collect();
            let mut parser = HopPatternParser::new(&tokens);
            parser.parse().unwrap().0.remove(0)
        }

        #[test]
        fn should_generate_hop_patterns() {
            let token = HopPatternLexer::new("1-ff00:0:133#1 2-1").tokenize();
            let expr = HopPatternParser::new(&token).parse().unwrap();

            let (first, second) = (&expr.0[0], &expr.0[1]);
            match first {
                HopPatternExpression::HopPredicate(s) if s.isd == Isd(1) => {}
                other => panic!("Expected HopPredicate(Isd(1)), got: {other:?}"),
            }

            match second {
                HopPatternExpression::HopPredicate(s) if s.isd == Isd(2) => {}
                other => panic!("Expected HopPredicate(Isd(2)), got: {other:?}"),
            }
        }

        #[test]
        fn should_parse_single_predicate() {
            let expr = parse_single_expression(vec![TokenKind::HopPredicate("1".into())]);
            match expr {
                HopPatternExpression::HopPredicate(ref s) if s.isd == Isd(1) => {}
                other => panic!("Expected HopPredicate(Isd(1)), got: {other:?}"),
            }
        }

        #[test]
        fn should_parse_parentheses() {
            let expr = parse_single_expression(vec![
                TokenKind::LParen,
                TokenKind::HopPredicate("1".into()),
                TokenKind::Or,
                TokenKind::HopPredicate("2".into()),
                TokenKind::RParen,
                TokenKind::Or,
                TokenKind::HopPredicate("3".into()),
            ]);

            match expr {
                HopPatternExpression::Or(lhs, rhs) => {
                    match *lhs {
                        HopPatternExpression::Or(..) => {}
                        ref other => {
                            panic!("Expected Or inside parentheses on LHS, got: {other:?}")
                        }
                    }
                    match *rhs {
                        HopPatternExpression::HopPredicate(_) => {}
                        ref other => panic!("Expected HopPredicate on RHS, got: {other:?}"),
                    }
                }
                other => panic!("Expected And at root, got: {other:?}"),
            }
        }

        #[test]
        fn should_parse_postfix_optional() {
            let expr = parse_single_expression(vec![
                TokenKind::HopPredicate("1".into()),
                TokenKind::QMark,
            ]);
            match expr {
                HopPatternExpression::Optional(inner) => {
                    match *inner {
                        HopPatternExpression::HopPredicate(_) => {}
                        ref other => {
                            panic!("Expected HopPredicate inside Optional, got: {other:?}")
                        }
                    }
                }
                other => panic!("Expected Optional, got: {other:?}"),
            }
        }

        #[test]
        fn should_parse_postfix_plus() {
            let expr =
                parse_single_expression(vec![TokenKind::HopPredicate("1".into()), TokenKind::Plus]);
            match expr {
                HopPatternExpression::OneOrMore(inner) => {
                    match *inner {
                        HopPatternExpression::HopPredicate(_) => {}
                        ref other => {
                            panic!("Expected HopPredicate inside OneOrMore, got: {other:?}")
                        }
                    }
                }
                other => panic!("Expected OneOrMore, got: {other:?}"),
            }
        }

        #[test]
        fn should_parse_postfix_star() {
            let expr =
                parse_single_expression(vec![TokenKind::HopPredicate("1".into()), TokenKind::Star]);
            match expr {
                HopPatternExpression::ZeroOrMore(inner) => {
                    match *inner {
                        HopPatternExpression::HopPredicate(_) => {}
                        ref other => {
                            panic!("Expected HopPredicate inside ZeroOrMore, got: {other:?}")
                        }
                    }
                }
                other => panic!("Expected ZeroOrMore, got: {other:?}"),
            }
        }

        #[test]
        fn should_parse_chained_postfix() {
            let expr = parse_single_expression(vec![
                TokenKind::HopPredicate("1".into()),
                TokenKind::QMark,
                TokenKind::Plus,
                TokenKind::Star,
            ]);

            match expr {
                HopPatternExpression::ZeroOrMore(inner1) => {
                    match *inner1 {
                        HopPatternExpression::OneOrMore(inner2) => {
                            match *inner2 {
                                HopPatternExpression::Optional(inner3) => {
                                    match *inner3 {
                                        HopPatternExpression::HopPredicate(_) => {}
                                        ref other => {
                                            panic!(
                                                "Expected HopPredicate inside Optional, got: {other:?}"
                                            )
                                        }
                                    }
                                }
                                ref other => {
                                    panic!("Expected Optional inside OneOrMore, got: {other:?}")
                                }
                            }
                        }
                        ref other => {
                            panic!("Expected OneOrMore inside ZeroOrMore, got: {other:?}")
                        }
                    }
                }
                other => panic!("Expected ZeroOrMore at root, got: {other:?}"),
            }
        }

        mod error_tests {
            use super::*;

            #[test]
            fn should_error_on_unexpected_token() {
                let tokens = vec![tok(TokenKind::And), tok(TokenKind::EOI)];
                let mut parser = HopPatternParser::new(&tokens);
                let err = parser.parse().unwrap_err();
                assert!(
                    err.message.contains("unexpected token"),
                    "Expected error message to contain 'unexpected token', got: {:?}",
                    err.message
                );
            }

            #[test]
            fn should_error_on_unexpected_end() {
                let tokens = vec![tok(TokenKind::LParen)];
                let mut parser = HopPatternParser::new(&tokens);
                let err = parser.parse().unwrap_err();
                assert!(
                    err.message.contains("unexpected end"),
                    "Expected error message to contain 'unexpected end', got: {:?}",
                    err.message
                );
            }

            #[test]
            fn should_error_on_unexpected_trailing_tokens() {
                let tokens = vec![
                    tok(TokenKind::HopPredicate("1".into())),
                    tok(TokenKind::HopPredicate("2".into())),
                    tok(TokenKind::EOI),
                    tok(TokenKind::Bang),
                ];
                let mut parser = HopPatternParser::new(&tokens);
                let err = parser.parse().unwrap_err();
                assert!(
                    err.message.contains("unexpected trailing"),
                    "Expected error message to contain 'unexpected trailing', got: {:?}",
                    err.message
                );
            }
        }
    }
}
