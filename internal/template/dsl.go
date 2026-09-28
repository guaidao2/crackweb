package template

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Value is the result of evaluating a DSL expression: a string, a number or a
// boolean, which is all the expressions in real templates produce.
type Value struct {
	str  string
	num  float64
	kind valueKind
}

type valueKind int

const (
	kindString valueKind = iota
	kindNumber
	kindBool
)

// StringValue and friends build typed values.
func StringValue(s string) Value  { return Value{str: s, kind: kindString} }
func NumberValue(f float64) Value { return Value{num: f, kind: kindNumber} }
func BoolValue(b bool) Value {
	if b {
		return Value{num: 1, kind: kindBool}
	}
	return Value{num: 0, kind: kindBool}
}

// String renders a value as text.
func (v Value) String() string {
	switch v.kind {
	case kindNumber:
		return strconv.FormatFloat(v.num, 'f', -1, 64)
	case kindBool:
		if v.num != 0 {
			return "true"
		}
		return "false"
	default:
		return v.str
	}
}

// Number renders a value as a float, parsing strings when needed.
func (v Value) Number() float64 {
	if v.kind == kindString {
		parsed, _ := strconv.ParseFloat(strings.TrimSpace(v.str), 64)
		return parsed
	}
	return v.num
}

// Truthy reports whether a value counts as true in a boolean context.
func (v Value) Truthy() bool {
	switch v.kind {
	case kindBool, kindNumber:
		return v.num != 0
	default:
		return strings.TrimSpace(v.str) != ""
	}
}

// EvalError is raised for an expression that cannot be evaluated.
type EvalError struct{ msg string }

func (e *EvalError) Error() string { return e.msg }

func evalErrorf(format string, args ...any) error {
	return &EvalError{msg: fmt.Sprintf(format, args...)}
}

// Eval evaluates a DSL expression against a set of variables.
func Eval(expression string, vars map[string]Value) (Value, error) {
	parser := &dslParser{input: expression, vars: vars}
	parser.next()
	value, err := parser.parseOr()
	if err != nil {
		return Value{}, err
	}
	if parser.token.kind != tokenEOF {
		return Value{}, evalErrorf("unexpected %q at position %d", parser.token.text, parser.token.pos)
	}
	return value, nil
}

// EvalBool evaluates an expression and coerces the result to a boolean.
func EvalBool(expression string, vars map[string]Value) (bool, error) {
	value, err := Eval(expression, vars)
	if err != nil {
		return false, err
	}
	return value.Truthy(), nil
}

// --- lexer --------------------------------------------------------------

type tokenKind int

const (
	tokenEOF tokenKind = iota
	tokenIdentifier
	tokenNumber
	tokenString
	tokenOperator
	tokenLParen
	tokenRParen
	tokenComma
)

type token struct {
	kind tokenKind
	text string
	num  float64
	pos  int
}

// dslParser is a hand-written recursive-descent parser. A dependency-free
// evaluator is worth its ninety lines here: the grammar templates use is tiny,
// and pulling in an expression library would mean auditing its escape hatches.
type dslParser struct {
	input string
	pos   int
	token token
	vars  map[string]Value
}

// operatorTwoChar are the operators written with two characters.
var operatorTwoChar = []string{"&&", "||", "==", "!=", "<=", ">="}

// operatorOneChar are the single-character operators.
const operatorOneChar = "!<>"

// next advances to the next token.
func (p *dslParser) next() {
	for p.pos < len(p.input) && isSpace(p.input[p.pos]) {
		p.pos++
	}
	if p.pos >= len(p.input) {
		p.token = token{kind: tokenEOF, pos: p.pos}
		return
	}

	start := p.pos
	ch := p.input[p.pos]

	switch {
	case ch == '(':
		p.pos++
		p.token = token{kind: tokenLParen, text: "(", pos: start}
	case ch == ')':
		p.pos++
		p.token = token{kind: tokenRParen, text: ")", pos: start}
	case ch == ',':
		p.pos++
		p.token = token{kind: tokenComma, text: ",", pos: start}
	case ch == '\'' || ch == '"':
		quote := ch
		p.pos++
		var b strings.Builder
		for p.pos < len(p.input) && p.input[p.pos] != quote {
			if p.input[p.pos] == '\\' && p.pos+1 < len(p.input) {
				p.pos++
				switch p.input[p.pos] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				default:
					b.WriteByte(p.input[p.pos])
				}
				p.pos++
				continue
			}
			b.WriteByte(p.input[p.pos])
			p.pos++
		}
		if p.pos < len(p.input) {
			p.pos++ // closing quote
		}
		p.token = token{kind: tokenString, text: b.String(), pos: start}

	case ch >= '0' && ch <= '9':
		for p.pos < len(p.input) && (isDigit(p.input[p.pos]) || p.input[p.pos] == '.') {
			p.pos++
		}
		text := p.input[start:p.pos]
		number, _ := strconv.ParseFloat(text, 64)
		p.token = token{kind: tokenNumber, text: text, num: number, pos: start}

	case isIdentStart(ch):
		for p.pos < len(p.input) && isIdentPart(p.input[p.pos]) {
			p.pos++
		}
		p.token = token{kind: tokenIdentifier, text: p.input[start:p.pos], pos: start}

	default:
		for _, op := range operatorTwoChar {
			if strings.HasPrefix(p.input[p.pos:], op) {
				p.pos += len(op)
				p.token = token{kind: tokenOperator, text: op, pos: start}
				return
			}
		}
		if strings.IndexByte(operatorOneChar, ch) >= 0 {
			p.pos++
			p.token = token{kind: tokenOperator, text: string(ch), pos: start}
			return
		}
		// Not an operator and not a valid start: consume it, so the parser can
		// report a sensible error rather than looping.
		p.pos++
		p.token = token{kind: tokenOperator, text: string(ch), pos: start}
	}
}

func (p *dslParser) expect(kind tokenKind, what string) error {
	if p.token.kind != kind {
		return evalErrorf("expected %s at position %d, found %q", what, p.token.pos, p.token.text)
	}
	return nil
}

// parseOr handles "a || b".
func (p *dslParser) parseOr() (Value, error) {
	left, err := p.parseAnd()
	if err != nil {
		return Value{}, err
	}
	for p.token.kind == tokenOperator && p.token.text == "||" {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return Value{}, err
		}
		left = BoolValue(left.Truthy() || right.Truthy())
	}
	return left, nil
}

// parseAnd handles "a && b".
func (p *dslParser) parseAnd() (Value, error) {
	left, err := p.parseComparison()
	if err != nil {
		return Value{}, err
	}
	for p.token.kind == tokenOperator && p.token.text == "&&" {
		p.next()
		right, err := p.parseComparison()
		if err != nil {
			return Value{}, err
		}
		left = BoolValue(left.Truthy() && right.Truthy())
	}
	return left, nil
}

// parseComparison handles the binary comparison operators.
func (p *dslParser) parseComparison() (Value, error) {
	left, err := p.parseUnary()
	if err != nil {
		return Value{}, err
	}
	if p.token.kind != tokenOperator {
		return left, nil
	}

	op := p.token.text
	switch op {
	case "==", "!=", "<", ">", "<=", ">=":
	default:
		return left, nil
	}
	p.next()

	right, err := p.parseUnary()
	if err != nil {
		return Value{}, err
	}
	return BoolValue(compare(op, left, right)), nil
}

// parseUnary handles "!x".
func (p *dslParser) parseUnary() (Value, error) {
	if p.token.kind == tokenOperator && p.token.text == "!" {
		p.next()
		value, err := p.parseUnary()
		if err != nil {
			return Value{}, err
		}
		return BoolValue(!value.Truthy()), nil
	}
	return p.parsePrimary()
}

// parsePrimary handles literals, variables, function calls and parentheses.
func (p *dslParser) parsePrimary() (Value, error) {
	switch p.token.kind {
	case tokenNumber:
		value := NumberValue(p.token.num)
		p.next()
		return value, nil

	case tokenString:
		value := StringValue(p.token.text)
		p.next()
		return value, nil

	case tokenLParen:
		p.next()
		value, err := p.parseOr()
		if err != nil {
			return Value{}, err
		}
		if err := p.expect(tokenRParen, ")"); err != nil {
			return Value{}, err
		}
		p.next()
		return value, nil

	case tokenIdentifier:
		name := p.token.text
		p.next()
		if p.token.kind == tokenLParen {
			return p.parseCall(name)
		}
		return p.lookup(name)

	default:
		return Value{}, evalErrorf("unexpected %q at position %d", p.token.text, p.token.pos)
	}
}

// parseCall evaluates a function invocation.
func (p *dslParser) parseCall(name string) (Value, error) {
	p.next() // consume "("
	var args []Value
	if p.token.kind != tokenRParen {
		for {
			arg, err := p.parseOr()
			if err != nil {
				return Value{}, err
			}
			args = append(args, arg)
			if p.token.kind != tokenComma {
				break
			}
			p.next()
		}
	}
	if err := p.expect(tokenRParen, ")"); err != nil {
		return Value{}, err
	}
	p.next()
	return callFunction(name, args)
}

// lookup resolves an identifier to a variable.
func (p *dslParser) lookup(name string) (Value, error) {
	if value, ok := p.vars[name]; ok {
		return value, nil
	}
	// An unknown identifier is not fatal: a template referring to a variable
	// crackweb does not provide should evaluate to empty rather than abort the
	// whole check.
	switch strings.ToLower(name) {
	case "true":
		return BoolValue(true), nil
	case "false":
		return BoolValue(false), nil
	}
	return StringValue(""), nil
}

// compare applies a comparison operator, choosing numeric or string semantics
// from the operands.
func compare(op string, a, b Value) bool {
	numeric := (a.kind == kindNumber || b.kind == kindNumber) &&
		(a.kind != kindString && b.kind != kindString)

	if numeric {
		x, y := a.Number(), b.Number()
		switch op {
		case "==":
			return x == y
		case "!=":
			return x != y
		case "<":
			return x < y
		case ">":
			return x > y
		case "<=":
			return x <= y
		case ">=":
			return x >= y
		}
	}

	x, y := a.String(), b.String()
	switch op {
	case "==":
		return x == y
	case "!=":
		return x != y
	case "<":
		return x < y
	case ">":
		return x > y
	case "<=":
		return x <= y
	case ">=":
		return x >= y
	}
	return false
}

// callFunction dispatches a DSL helper function.
func callFunction(name string, args []Value) (Value, error) {
	lower := strings.ToLower(name)
	str := func(i int) string {
		if i < len(args) {
			return args[i].String()
		}
		return ""
	}

	switch lower {
	case "contains":
		if len(args) < 2 {
			return BoolValue(false), nil
		}
		return BoolValue(strings.Contains(str(0), str(1))), nil

	case "contains_all":
		if len(args) < 2 {
			return BoolValue(false), nil
		}
		for _, arg := range args[1:] {
			if !strings.Contains(str(0), arg.String()) {
				return BoolValue(false), nil
			}
		}
		return BoolValue(true), nil

	case "contains_any":
		for _, arg := range args[1:] {
			if strings.Contains(str(0), arg.String()) {
				return BoolValue(true), nil
			}
		}
		return BoolValue(false), nil

	case "starts_with", "startswith":
		if len(args) < 2 {
			return BoolValue(false), nil
		}
		return BoolValue(strings.HasPrefix(str(0), str(1))), nil

	case "ends_with", "endswith":
		if len(args) < 2 {
			return BoolValue(false), nil
		}
		return BoolValue(strings.HasSuffix(str(0), str(1))), nil

	case "len", "length":
		return NumberValue(float64(len(str(0)))), nil

	case "tolower", "to_lower":
		return StringValue(strings.ToLower(str(0))), nil

	case "toupper", "to_upper":
		return StringValue(strings.ToUpper(str(0))), nil

	case "trim", "trim_space":
		return StringValue(strings.TrimSpace(str(0))), nil

	case "replace":
		if len(args) < 3 {
			return StringValue(str(0)), nil
		}
		return StringValue(strings.ReplaceAll(str(0), str(1), str(2))), nil

	case "concat":
		var b strings.Builder
		for _, arg := range args {
			b.WriteString(arg.String())
		}
		return StringValue(b.String()), nil

	case "reverse":
		runes := []rune(str(0))
		for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
			runes[i], runes[j] = runes[j], runes[i]
		}
		return StringValue(string(runes)), nil

	case "substr":
		runes := []rune(str(0))
		start := int(args[1].Number())
		if start < 0 || start > len(runes) {
			return StringValue(""), nil
		}
		end := len(runes)
		if len(args) > 2 {
			end = start + int(args[2].Number())
			if end > len(runes) {
				end = len(runes)
			}
		}
		return StringValue(string(runes[start:end])), nil

	case "regex", "regex_match":
		if len(args) < 2 {
			return BoolValue(false), nil
		}
		re, err := regexp.Compile(str(0))
		if err != nil {
			return BoolValue(false), nil
		}
		return BoolValue(re.MatchString(str(1))), nil

	case "md5":
		sum := md5.Sum([]byte(str(0)))
		return StringValue(hex.EncodeToString(sum[:])), nil

	case "sha1":
		sum := sha1.Sum([]byte(str(0)))
		return StringValue(hex.EncodeToString(sum[:])), nil

	case "sha256":
		sum := sha256.Sum256([]byte(str(0)))
		return StringValue(hex.EncodeToString(sum[:])), nil

	case "base64", "base64_encode":
		return StringValue(base64.StdEncoding.EncodeToString([]byte(str(0)))), nil

	case "base64_decode":
		decoded, err := base64.StdEncoding.DecodeString(str(0))
		if err != nil {
			return StringValue(""), nil
		}
		return StringValue(string(decoded)), nil

	case "url_encode", "urlencode":
		return StringValue(url.QueryEscape(str(0))), nil

	case "url_decode", "urldecode":
		decoded, err := url.QueryUnescape(str(0))
		if err != nil {
			return StringValue(str(0)), nil
		}
		return StringValue(decoded), nil

	case "hex_encode":
		return StringValue(hex.EncodeToString([]byte(str(0)))), nil

	case "hex_decode":
		decoded, err := hex.DecodeString(str(0))
		if err != nil {
			return StringValue(""), nil
		}
		return StringValue(string(decoded)), nil

	case "to_number", "tonumber":
		return NumberValue(args[0].Number()), nil

	case "rand_int":
		limit := 1000000
		if len(args) > 0 && args[0].Number() > 0 {
			limit = int(args[0].Number())
		}
		return NumberValue(float64(rand.IntN(limit))), nil

	case "randstr", "rand_base", "rand_text_alphanumeric":
		length := 8
		if len(args) > 0 && args[0].Number() > 0 {
			length = int(args[0].Number())
		}
		return StringValue(randomString(length)), nil

	case "unix_time", "unixtime":
		return NumberValue(float64(time.Now().Unix())), nil
	}

	return Value{}, evalErrorf("unknown DSL function %q", name)
}

// randomAlphabet is the character set used by the random-string helpers.
const randomAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// randomString returns a random alphanumeric string.
func randomString(length int) string {
	if length <= 0 || length > 4096 {
		length = 8
	}
	var b strings.Builder
	b.Grow(length)
	for i := 0; i < length; i++ {
		b.WriteByte(randomAlphabet[rand.IntN(len(randomAlphabet))])
	}
	return b.String()
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func isIdentStart(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isIdentPart(b byte) bool { return isIdentStart(b) || isDigit(b) || b == '.' }
