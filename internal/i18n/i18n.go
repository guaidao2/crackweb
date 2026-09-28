// Package i18n holds crackweb's user-facing message catalogue.
//
// crackweb ships English by default because it is a MIT-licensed tool aimed at
// a global audience; Simplified Chinese is available as an explicit opt-in.
// English is the fallback for any key a translation misses, so a half-finished
// translation degrades to English instead of printing blank lines.
package i18n

import (
	"os"
	"strings"
)

// Lang identifies a message catalogue.
type Lang string

// Supported languages.
const (
	// EN is English, the default.
	EN Lang = "en"
	// ZH is Simplified Chinese, opt-in via --lang zh or CRACKWEB_LANG=zh.
	ZH Lang = "zh"
)

// Default is the language used when nothing else is requested.
const Default = EN

// ParseLang normalises a user-supplied language tag into a Lang.
// It accepts the tags people actually type: en, english, zh, zh-cn, zh_cn,
// chinese, cn, as well as locale strings such as zh-Hans-CN.
func ParseLang(s string) (Lang, bool) {
	tag := strings.ToLower(strings.TrimSpace(s))
	if tag == "" {
		return "", false
	}
	// Cut the encoding part of a POSIX locale: zh_CN.UTF-8 -> zh_cn.
	if i := strings.IndexAny(tag, "."); i >= 0 {
		tag = tag[:i]
	}
	switch {
	case tag == "en", tag == "english", strings.HasPrefix(tag, "en-"), strings.HasPrefix(tag, "en_"):
		return EN, true
	case tag == "zh", tag == "cn", tag == "chinese", tag == "zh-hans", tag == "zh-hant",
		strings.HasPrefix(tag, "zh-"), strings.HasPrefix(tag, "zh_"):
		return ZH, true
	}
	return "", false
}

// Detect resolves the language to use, in priority order:
//
//  1. explicit — the value of --lang, when the user passed it
//  2. CRACKWEB_LANG — the tool's own environment variable
//  3. Default (English)
//
// The POSIX locale is deliberately *not* consulted. crackweb's contract is
// English by default, with Chinese switched on explicitly; silently following
// an inherited LC_ALL/LANG would make the output language depend on the machine
// a scan happens to run on, which is exactly the surprise this avoids.
//
// Anything unrecognised is ignored rather than treated as an error, so a stray
// environment variable never breaks a run.
func Detect(explicit string) Lang {
	if lang, ok := ParseLang(explicit); ok {
		return lang
	}
	if lang, ok := ParseLang(os.Getenv("CRACKWEB_LANG")); ok {
		return lang
	}
	return Default
}

// Key identifies one translatable message.
type Key string

// Bundle is a resolved message catalogue for a single language.
type Bundle struct {
	lang Lang
	msgs map[Key]string
}

// New returns the catalogue for lang, falling back to Default when lang is
// unknown. The returned Bundle owns a copy of the message table, so callers
// can adjust or extend it without mutating the shared catalogues.
func New(lang Lang) *Bundle {
	src, ok := catalogues[lang]
	if !ok {
		lang, src = Default, catalogues[Default]
	}
	msgs := make(map[Key]string, len(src))
	for key, msg := range src {
		msgs[key] = msg
	}
	return &Bundle{lang: lang, msgs: msgs}
}

// Lang reports the language this bundle resolved to.
func (b *Bundle) Lang() Lang { return b.lang }

// T looks a message up. With no arguments the message is returned verbatim,
// which keeps stray '%' characters in translated text harmless; with arguments
// it is treated as a fmt format string.
func (b *Bundle) T(key Key, args ...any) string {
	msg := b.text(key)
	if len(args) == 0 {
		return msg
	}
	return sprintf(msg, args...)
}

// text returns the translation, falling back to English and finally to the raw
// key so that a missing entry is visible rather than silent.
func (b *Bundle) text(key Key) string {
	if msg, ok := b.msgs[key]; ok {
		return msg
	}
	if msg, ok := catalogues[Default][key]; ok {
		return msg
	}
	return string(key)
}

// Has reports whether key is translated in this bundle's own catalogue.
// Callers use it for diagnostics; T never needs it.
func (b *Bundle) Has(key Key) bool {
	_, ok := b.msgs[key]
	return ok
}

// catalogueFor exposes a raw catalogue; used by the tests that keep the
// translations in sync.
func catalogueFor(lang Lang) map[Key]string { return catalogues[lang] }
