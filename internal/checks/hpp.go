package checks

import (
	"context"
	"errors"
	"strconv"

	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/payload"
)

// MutateHPP builds a request that carries the parameter twice: the original
// value first, and the payload as a second occurrence of the same name.
//
// The technique works because the layers disagree about which occurrence wins.
// A filter commonly inspects the first, many frameworks resolve the last, and
// some concatenate both. So the payload travels in the shadow of the value that
// was checked — no obfuscation needed, just a disagreement about parsing.
//
// Duplicating rather than replacing is the whole point: replacing would put the
// payload where the filter is looking.
func MutateHPP(req *httpmsg.Request, param httpmsg.Param, payloadText string, enc Encoding) (*httpmsg.Request, error) {
	if req == nil {
		return nil, errors.New("checks: cannot mutate a nil request")
	}
	out := req.Clone()
	raw := encodeValue(payloadText, enc)

	switch param.In {
	case httpmsg.LocQuery:
		if out.URL == nil {
			return nil, errors.New("checks: request has no URL")
		}
		// The original pair list is left untouched; the duplicate is appended.
		if out.URL.RawQuery == "" {
			out.URL.RawQuery = param.RawName + "=" + raw
		} else {
			out.URL.RawQuery += "&" + param.RawName + "=" + raw
		}

	case httpmsg.LocBody:
		body := string(out.Body)
		if body == "" {
			body = param.RawName + "=" + raw
		} else {
			body += "&" + param.RawName + "=" + raw
		}
		out.Body = []byte(body)
		out.Header.Set("Content-Length", strconv.Itoa(len(out.Body)))

	default:
		// A cookie header has its own duplicate semantics, and a header
		// parameter has none. Neither is worth guessing at.
		return nil, errors.New("checks: HPP is not defined for " + string(param.In))
	}
	return out, nil
}

// tryVariantHPP sends the same variant as a polluted parameter pair.
func (c *Context) tryVariantHPP(ctx context.Context, t *Target, variant payload.Variant) (*Attempt, error) {
	request, err := MutateHPP(t.Request, *t.Param, variant.Value, EncodingForVariant(variant))
	if err != nil {
		return nil, err
	}
	response, err := c.Do(ctx, request)
	if err != nil {
		return nil, err
	}
	attempt := &Attempt{Request: request, Response: response, Variant: variant}
	attempt.Blocked = c.WAF.IsBlocked(request.Hostname(), response)
	attempt.Polluted = true
	return attempt, nil
}
