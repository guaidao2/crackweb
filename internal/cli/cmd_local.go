package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/local"
)

// localOptions is the parsed command line of "crackweb local".
type localOptions struct {
	wordlist *string
}

// newLocalCommand builds the offline command: work done on an artifact the operator already
// has, with nothing sent anywhere.
func newLocalCommand() *command {
	return newCommand("local", i18n.KeyCmdLocalSummary, i18n.KeyUsageLocal,
		func(fs *FlagSet) *localOptions {
			return &localOptions{
				wordlist: fs.String("wordlist", "w", "", "<file>", i18n.KeyFlagLocalWordlist),
			}
		},
		runLocal)
}

// runLocal dispatches the offline analyses. "jwt" is the first of them; the shape is a
// subcommand so the next one does not need a new top-level command.
func runLocal(app *App, opts *localOptions, args []string) error {
	if len(args) == 0 {
		return &UsageError{msg: app.T(i18n.KeyErrLocalNoSubject)}
	}
	switch args[0] {
	case "jwt":
		return runLocalJWT(app, opts, args[1:])
	default:
		return &UsageError{msg: fmt.Sprintf(app.T(i18n.KeyErrLocalUnknownSubject), args[0])}
	}
}

// runLocalJWT decodes a token, says what it is signed with, and tries to find the secret that
// signed it.
func runLocalJWT(app *App, opts *localOptions, args []string) error {
	if len(args) == 0 {
		return &UsageError{msg: app.T(i18n.KeyErrLocalNoToken)}
	}

	token, err := local.Parse(args[0])
	if err != nil {
		return &UsageError{msg: fmt.Sprintf(app.T(i18n.KeyErrLocalBadToken), err)}
	}

	printJSON(app, app.T(i18n.KeyMsgLocalHeader), token.Header)
	printJSON(app, app.T(i18n.KeyMsgLocalClaims), token.Claims)

	algorithm := token.Algorithm()
	if algorithm == "" {
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

	if !token.Symmetric() {
		// Nothing to crack: an asymmetric signature is not a function of a guessable secret.
		app.Note(i18n.KeyMsgLocalNotSymmetric, algorithm)
		return nil
	}
	if !token.Signed() {
		return nil
	}

	var fromFile []string
	if *opts.wordlist != "" {
		fromFile, err = local.ReadWordlist(*opts.wordlist)
		if err != nil {
			return &UsageError{msg: fmt.Sprintf(app.T(i18n.KeyErrLocalWordlist), err)}
		}
	}
	candidates := local.SecretCandidates(token, fromFile)
	app.Note(i18n.KeyMsgLocalTrying, len(candidates))

	result, found := local.Crack(token, candidates)
	if !found {
		app.Note(i18n.KeyMsgLocalNoSecret, len(candidates))
		return nil
	}

	// The secret reproduces the signature, which is arithmetic and certain. Saying how it was
	// found matters: a derived candidate means the signing key is built from something the
	// token itself publishes.
	app.Warn(i18n.KeyMsgLocalSecretFound, result.Secret, result.Tried)
	if result.Index < len(fromFile) {
		app.Note(i18n.KeyMsgLocalSecretFromFile)
	} else if result.Index < len(fromFile)+len(local.DefaultSecrets) {
		app.Note(i18n.KeyMsgLocalSecretFromDefaults)
	} else {
		app.Note(i18n.KeyMsgLocalSecretDerived)
	}
	// Compare the signature, not the whole token: re-encoding the header can reorder its
	// fields, and the signature is the thing the secret determines.
	app.Note(i18n.KeyMsgLocalSigned, strings.HasSuffix(token.SignHMAC([]byte(result.Secret)), token.Signature))
	return nil
}

// printJSON writes an object the way a reader checks it: one field per line, so a value can be
// read against its key without a JSON tool.
func printJSON(app *App, title string, object map[string]any) {
	app.Note(i18n.KeyMsgLocalField, title, "")
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
