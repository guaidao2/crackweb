package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/local"
)

// localSubjects are the offline analyses.
//
// Each is a command in its own right, so it declares its own options and gets its own help —
// the two have nothing in common to parse, and sharing one option set would put `--wordlist`
// in the help of a subject that has no use for it.
func localSubjects() []*command {
	return []*command{
		newLocalJWTCommand(),
		newLocalHashCommand(),
	}
}

// newLocalCommand builds the offline command: work done on an artifact the operator already
// has, with nothing sent anywhere.
func newLocalCommand() *command {
	cmd := newCommand("local", i18n.KeyCmdLocalSummary, i18n.KeyUsageLocal,
		func(fs *FlagSet) *struct{} {
			// The subjects carry the options; this level only lists and dispatches.
			return &struct{}{}
		},
		runLocal)
	cmd.subcommands = localSubjects()
	return cmd
}

// runLocal lists the subjects, which is what is left to do here: a named subject is dispatched
// by the framework before this runs.
func runLocal(app *App, _ *struct{}, args []string) error {
	if len(args) > 0 {
		return &UsageError{msg: fmt.Sprintf(app.T(i18n.KeyErrLocalUnknownSubject), args[0])}
	}
	app.Note(i18n.KeyMsgLocalSubjects)
	for _, subject := range localSubjects() {
		app.Printf("  %-6s %s", subject.name, app.T(subject.summary))
	}
	return &UsageError{msg: app.T(i18n.KeyErrLocalNoSubject)}
}

// jwtLocalOptions is the parsed command line of "crackweb local jwt".
type jwtLocalOptions struct {
	wordlist *string
	secret   *string
	forge    *bool
	claim    *[]string
}

// newLocalJWTCommand builds the token analysis.
func newLocalJWTCommand() *command {
	return newCommand("jwt", i18n.KeyCmdLocalJWTTitle, i18n.KeyUsageLocalJWT,
		func(fs *FlagSet) *jwtLocalOptions {
			return &jwtLocalOptions{
				wordlist: fs.String("wordlist", "w", "", "<file>", i18n.KeyFlagLocalWordlist),
				secret:   fs.String("secret", "s", "", "<value>", i18n.KeyFlagLocalSecret),
				forge:    fs.Bool("forge", "", i18n.KeyFlagLocalForge),
				claim:    fs.StringSlice("claim", "c", "<name=value>", i18n.KeyFlagLocalClaim),
			}
		},
		runLocalJWT)
}

// runLocalJWT decodes a token, says what it is signed with, tries to find the secret behind it,
// and — given a secret — can sign one of its own.
func runLocalJWT(app *App, opts *jwtLocalOptions, args []string) error {
	if len(args) == 0 {
		return &UsageError{msg: app.T(i18n.KeyErrLocalNoToken)}
	}
	token, err := local.Parse(args[0])
	if err != nil {
		return &UsageError{msg: fmt.Sprintf(app.T(i18n.KeyErrLocalBadToken), err)}
	}

	printObject(app, app.T(i18n.KeyMsgLocalHeader), token.Header)
	printObject(app, app.T(i18n.KeyMsgLocalClaims), token.Claims)
	reportTokenProperties(app, token)

	// A secret supplied on the command line is used as given; otherwise every candidate is
	// tried, which is where a token from a config file usually gives up its key.
	secret := strings.TrimSpace(*opts.secret)
	if secret == "" {
		secret, err = recoverSecret(app, token, *opts.wordlist)
		if err != nil {
			return err
		}
	}

	if !*opts.forge {
		return nil
	}
	if secret == "" {
		return &UsageError{msg: app.T(i18n.KeyErrLocalForgeNeedsSecret)}
	}
	if !token.Symmetric() {
		return &UsageError{msg: fmt.Sprintf(app.T(i18n.KeyErrLocalForgeNotSymmetric), token.Algorithm())}
	}
	return forgeToken(app, token, secret, *opts.claim)
}

// recoverSecret tries everything known against the token and says what it found. It returns the
// empty string when the token cannot be signed from a guess or no candidate fits, both of which
// are ordinary outcomes rather than errors.
func recoverSecret(app *App, token *local.Token, wordlistPath string) (string, error) {
	if !token.Symmetric() || !token.Signed() {
		return "", nil
	}
	var fromFile []string
	if wordlistPath != "" {
		var err error
		if fromFile, err = local.ReadWordlist(wordlistPath); err != nil {
			return "", &UsageError{msg: fmt.Sprintf(app.T(i18n.KeyErrLocalWordlist), err)}
		}
	}
	candidates := local.SecretCandidates(token, fromFile)
	app.Note(i18n.KeyMsgLocalTrying, len(candidates))

	result, found := local.Crack(token, candidates)
	if !found {
		app.Note(i18n.KeyMsgLocalNoSecret, len(candidates))
		return "", nil
	}
	app.Warn(i18n.KeyMsgLocalSecretFound, result.Secret, result.Tried)
	switch {
	case result.Index < len(fromFile):
		app.Note(i18n.KeyMsgLocalSecretFromFile)
	case result.Index < len(fromFile)+len(local.DefaultSecrets):
		app.Note(i18n.KeyMsgLocalSecretFromDefaults)
	default:
		app.Note(i18n.KeyMsgLocalSecretDerived)
	}
	app.Note(i18n.KeyMsgLocalSigned, strings.HasSuffix(token.SignHMAC([]byte(result.Secret)), token.Signature))
	return result.Secret, nil
}

// forgeToken signs a token whose claims the operator named, which is the question that follows
// "I have the key": what can be issued with it.
func forgeToken(app *App, token *local.Token, secret string, claims []string) error {
	replaced := map[string]any{}
	for _, claim := range claims {
		name, value, found := strings.Cut(claim, "=")
		if !found || strings.TrimSpace(name) == "" {
			return &UsageError{msg: fmt.Sprintf(app.T(i18n.KeyErrLocalBadClaim), claim)}
		}
		replaced[strings.TrimSpace(name)] = local.ClaimFromValue(value)
	}

	forged, err := token.Forge([]byte(secret), replaced)
	if err != nil {
		return err
	}
	app.Printf("%s", forged)
	return nil
}

// hashLocalOptions is the parsed command line of "crackweb local hash".
type hashLocalOptions struct {
	wordlist *string
}

// newLocalHashCommand builds the hash analysis.
func newLocalHashCommand() *command {
	return newCommand("hash", i18n.KeyCmdLocalHashTitle, i18n.KeyUsageLocalHash,
		func(fs *FlagSet) *hashLocalOptions {
			return &hashLocalOptions{
				wordlist: fs.String("wordlist", "w", "", "<file>", i18n.KeyFlagLocalWordlist),
			}
		},
		runLocalHash)
}

// runLocalHash identifies a hash and, when it can, recovers the password behind it.
func runLocalHash(app *App, opts *hashLocalOptions, args []string) error {
	if len(args) == 0 {
		return &UsageError{msg: app.T(i18n.KeyErrLocalNoHash)}
	}

	value := args[0]
	kinds := local.Identify(value)
	if len(kinds) == 0 {
		app.Note(i18n.KeyMsgLocalHashUnknown)
		return nil
	}
	app.Note(i18n.KeyMsgLocalHashIdentified, len(kinds))
	for _, kind := range kinds {
		app.Printf("  %s", kind.Describe())
	}

	var crackable []local.HashKind
	for _, kind := range kinds {
		if kind.Crackable {
			crackable = append(crackable, kind)
		}
	}
	// A salted or memory-hard value is recognised and left alone: the point of saying what it
	// is stands on its own, and guessing at bcrypt is not what an offline mode is for.
	if len(crackable) == 0 {
		app.Note(i18n.KeyMsgLocalHashNotCrackable)
		return nil
	}

	var fromFile []string
	if *opts.wordlist != "" {
		var err error
		if fromFile, err = local.ReadWordlist(*opts.wordlist); err != nil {
			return &UsageError{msg: fmt.Sprintf(app.T(i18n.KeyErrLocalWordlist), err)}
		}
	}
	candidates := local.ReadCandidates(fromFile)
	app.Note(i18n.KeyMsgLocalHashTrying, len(candidates))

	result, found := local.CrackHash(value, crackable, candidates)
	if !found {
		app.Note(i18n.KeyMsgLocalHashNoPassword, len(candidates))
		return nil
	}
	app.Warn(i18n.KeyMsgLocalHashFound, result.Plaintext, result.Kind, result.Tried)
	return nil
}

// reportTokenProperties says what the token itself is, which is worth knowing whether or not a
// secret is recovered.
func reportTokenProperties(app *App, token *local.Token) {
	if algorithm := token.Algorithm(); algorithm == "" {
		app.Note(i18n.KeyMsgLocalNoAlgorithm)
	} else {
		app.Note(i18n.KeyMsgLocalAlgorithm, algorithm)
	}
	if !token.Signed() {
		app.Warn(i18n.KeyMsgLocalUnsigned)
	}
	if expiry, ok := token.Expiry(); ok {
		if time.Now().After(expiry) {
			app.Note(i18n.KeyMsgLocalExpired, expiry.Format(time.RFC3339))
		} else {
			app.Note(i18n.KeyMsgLocalValidUntil, expiry.Format(time.RFC3339))
		}
	}
}

// printObject writes an object the way a reader checks it: one field per line, so a value can be
// read against its key without a JSON tool.
func printObject(app *App, title string, object map[string]any) {
	app.Note(i18n.KeyMsgLocalField, title)
	for _, key := range sortedKeys(object) {
		value, _ := json.Marshal(object[key])
		app.Printf("    %-12s %s", key, strings.Trim(string(value), `"`))
	}
}

// sortedKeys returns a map's keys in a stable order, so the output does not shuffle between
// runs.
func sortedKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}
