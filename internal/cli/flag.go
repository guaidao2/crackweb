package cli

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/guaidao2/crackweb/internal/i18n"
)

// ErrHelp is returned by Parse when the user asked for help. Callers translate
// it into "print the usage and exit successfully".
var ErrHelp = errors.New("help requested")

// UsageError marks a problem with the command line itself, as opposed to a
// failure while running. main uses it to decide between exit code 2 (bad usage)
// and 1 (runtime failure).
type UsageError struct {
	msg string
}

func (e *UsageError) Error() string { return e.msg }

// IsUsageError reports whether err was caused by the command line.
func IsUsageError(err error) bool {
	var usage *UsageError
	return errors.As(err, &usage)
}

// Value is the storage behind one option.
type Value interface {
	Set(string) error
	String() string
}

// Flag is one registered option.
type Flag struct {
	// Long is the option name without dashes, e.g. "listen".
	Long string
	// Short is the single-character alias without a dash, or "".
	Short string
	// Arg is the placeholder shown in help for options that take a value,
	// e.g. "<addr>". Empty means the option is a boolean switch.
	Arg string
	// Help is the catalogue key for this option's description.
	Help i18n.Key
	// Value is the destination the parsed text is written to.
	Value Value

	set bool
}

// TakesValue reports whether the option consumes an argument.
func (f *Flag) TakesValue() bool { return f.Arg != "" }

// Label renders the option for help output, e.g. "-l, --listen <addr>".
func (f *Flag) Label() string {
	var b strings.Builder
	if f.Short != "" {
		b.WriteString("-" + f.Short + ", ")
	} else {
		b.WriteString("    ")
	}
	b.WriteString("--" + f.Long)
	if f.TakesValue() {
		b.WriteString(" " + f.Arg)
	}
	return b.String()
}

// FlagSet parses a command's options and renders them in the user's language.
//
// It is deliberately small and dependency-free, and — unlike the standard
// library — every diagnostic it can produce is a catalogue key, so a bad
// command line reads naturally in Chinese as well as English.
type FlagSet struct {
	bundle     *i18n.Bundle
	flags      []*Flag
	byLong     map[string]*Flag
	byShort    map[string]*Flag
	positional []string
}

// NewFlagSet returns an empty option set bound to a message catalogue.
func NewFlagSet(bundle *i18n.Bundle) *FlagSet {
	return &FlagSet{
		bundle:  bundle,
		byLong:  map[string]*Flag{},
		byShort: map[string]*Flag{},
	}
}

// Add registers an option.
func (fs *FlagSet) Add(flag *Flag) *Flag {
	fs.flags = append(fs.flags, flag)
	fs.byLong[flag.Long] = flag
	if flag.Short != "" {
		fs.byShort[flag.Short] = flag
	}
	return flag
}

// String registers a string option.
func (fs *FlagSet) String(long, short, def, arg string, help i18n.Key) *string {
	value := new(string)
	*value = def
	fs.Add(&Flag{Long: long, Short: short, Arg: arg, Help: help, Value: (*stringValue)(value)})
	return value
}

// StringSlice registers a repeatable string option.
func (fs *FlagSet) StringSlice(long, short, arg string, help i18n.Key) *[]string {
	value := new([]string)
	fs.Add(&Flag{Long: long, Short: short, Arg: arg, Help: help, Value: (*sliceValue)(value)})
	return value
}

// Bool registers a boolean switch.
func (fs *FlagSet) Bool(long, short string, help i18n.Key) *bool {
	value := new(bool)
	fs.Add(&Flag{Long: long, Short: short, Help: help, Value: (*boolValue)(value)})
	return value
}

// Int registers an integer option.
func (fs *FlagSet) Int(long, short string, def int, arg string, help i18n.Key) *int {
	value := new(int)
	*value = def
	fs.Add(&Flag{Long: long, Short: short, Arg: arg, Help: help, Value: (*intValue)(value)})
	return value
}

// Float registers a floating-point option.
func (fs *FlagSet) Float(long, short string, def float64, arg string, help i18n.Key) *float64 {
	value := new(float64)
	*value = def
	fs.Add(&Flag{Long: long, Short: short, Arg: arg, Help: help, Value: (*floatValue)(value)})
	return value
}

// Duration registers a duration option, accepting values like "10s" or "1m30s".
func (fs *FlagSet) Duration(long, short string, def time.Duration, arg string, help i18n.Key) *time.Duration {
	value := new(time.Duration)
	*value = def
	fs.Add(&Flag{Long: long, Short: short, Arg: arg, Help: help, Value: (*durationValue)(value)})
	return value
}

// Flags returns the registered options in registration order.
func (fs *FlagSet) Flags() []*Flag { return fs.flags }

// Args returns the positional arguments left over after parsing.
func (fs *FlagSet) Args() []string { return fs.positional }

// WasSet reports whether the named option appeared on the command line, which
// is how a command distinguishes "not given" from "given the default value".
func (fs *FlagSet) WasSet(long string) bool {
	flag, ok := fs.byLong[long]
	return ok && flag.set
}

// Parse consumes the command arguments. Options may be written as
// "--name value", "--name=value", "-n value" or "-n=value"; a bare "--" ends
// option processing; a lone "-" is a positional argument.
func (fs *FlagSet) Parse(args []string) error {
	fs.positional = nil
	for i := 0; i < len(args); i++ {
		token := args[i]

		switch {
		case token == "--":
			fs.positional = append(fs.positional, args[i+1:]...)
			return nil

		case token == "-" || !strings.HasPrefix(token, "-"):
			fs.positional = append(fs.positional, token)

		case token == "-h" || token == "--help":
			return ErrHelp

		case strings.HasPrefix(token, "--"):
			consumed, err := fs.parseLong(token, args[i+1:])
			if err != nil {
				return err
			}
			i += consumed

		default:
			consumed, err := fs.parseShort(token, args[i+1:])
			if err != nil {
				return err
			}
			i += consumed
		}
	}
	return nil
}

// parseLong handles a "--name" or "--name=value" token, returning how many
// following arguments it consumed.
func (fs *FlagSet) parseLong(token string, rest []string) (int, error) {
	name, inline, hasInline := strings.Cut(strings.TrimPrefix(token, "--"), "=")
	flag, ok := fs.byLong[name]
	if !ok {
		return 0, fs.usageError(i18n.KeyErrUnknownFlag, token)
	}
	return fs.assign(flag, token, inline, hasInline, rest)
}

// parseShort handles a "-n" or "-n=value" token.
func (fs *FlagSet) parseShort(token string, rest []string) (int, error) {
	body := strings.TrimPrefix(token, "-")
	name, inline, hasInline := strings.Cut(body, "=")
	flag, ok := fs.byShort[name]
	if !ok {
		return 0, fs.usageError(i18n.KeyErrUnknownFlag, token)
	}
	return fs.assign(flag, token, inline, hasInline, rest)
}

// assign writes the option's value, pulling the next argument when the option
// takes a value and none was given inline.
func (fs *FlagSet) assign(flag *Flag, token, inline string, hasInline bool, rest []string) (int, error) {
	if !flag.TakesValue() {
		flag.set = true
		if !hasInline {
			return 0, flag.Value.Set("true")
		}
		if err := flag.Value.Set(inline); err != nil {
			return 0, fs.invalidValue(inline, flag, err)
		}
		return 0, nil
	}

	if hasInline {
		flag.set = true
		if err := flag.Value.Set(inline); err != nil {
			return 0, fs.invalidValue(inline, flag, err)
		}
		return 0, nil
	}

	if len(rest) == 0 {
		return 0, fs.usageError(i18n.KeyErrFlagNeedsValue, flagLabel(flag, token))
	}
	flag.set = true
	if err := flag.Value.Set(rest[0]); err != nil {
		return 0, fs.invalidValue(rest[0], flag, err)
	}
	return 1, nil
}

// flagLabel names an option in an error message, preferring the spelling the
// user actually typed.
func flagLabel(flag *Flag, token string) string {
	if strings.Contains(token, "=") {
		return strings.SplitN(token, "=", 2)[0]
	}
	return token
}

func (fs *FlagSet) usageError(key i18n.Key, args ...any) error {
	return &UsageError{msg: fs.bundle.T(key, args...)}
}

func (fs *FlagSet) invalidValue(value string, flag *Flag, err error) error {
	return &UsageError{msg: fs.bundle.T(i18n.KeyErrInvalidValue, value, "--"+flag.Long, err.Error())}
}

// Help renders the option list, aligned and in the user's language.
func (fs *FlagSet) Help() string {
	if len(fs.flags) == 0 {
		return ""
	}
	labels := make([]string, len(fs.flags))
	width := 0
	for i, flag := range fs.flags {
		labels[i] = flag.Label()
		if n := len(labels[i]); n > width {
			width = n
		}
	}

	var b strings.Builder
	for i, flag := range fs.flags {
		fmt.Fprintf(&b, "  %-*s  %s\n", width, labels[i], fs.bundle.T(flag.Help))
	}
	return b.String()
}

// Value implementations. Each is a named pointer type so the FlagSet can hand
// out a plain *string / *bool / *int to the caller while still storing
// something that satisfies Value.

type stringValue string

func (v *stringValue) Set(s string) error { *v = stringValue(s); return nil }
func (v *stringValue) String() string     { return string(*v) }

type boolValue bool

func (v *boolValue) Set(s string) error {
	parsed, err := strconv.ParseBool(s)
	if err != nil {
		return fmt.Errorf("want true or false")
	}
	*v = boolValue(parsed)
	return nil
}
func (v *boolValue) String() string { return strconv.FormatBool(bool(*v)) }

type intValue int

func (v *intValue) Set(s string) error {
	parsed, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("want an integer")
	}
	*v = intValue(parsed)
	return nil
}
func (v *intValue) String() string { return strconv.Itoa(int(*v)) }

type sliceValue []string

func (v *sliceValue) Set(s string) error { *v = append(*v, s); return nil }
func (v *sliceValue) String() string     { return strings.Join(*v, ",") }

type floatValue float64

func (v *floatValue) Set(s string) error {
	parsed, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("want a number")
	}
	*v = floatValue(parsed)
	return nil
}
func (v *floatValue) String() string { return strconv.FormatFloat(float64(*v), 'g', -1, 64) }

type durationValue time.Duration

func (v *durationValue) Set(s string) error {
	// A bare number is read as seconds, which is what people type.
	if parsed, err := strconv.ParseFloat(s, 64); err == nil {
		*v = durationValue(time.Duration(parsed * float64(time.Second)))
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("want a duration such as 10s or 1m")
	}
	*v = durationValue(parsed)
	return nil
}
func (v *durationValue) String() string { return time.Duration(*v).String() }
