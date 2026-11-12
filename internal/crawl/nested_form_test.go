package crawl

import (
	"net/url"
	"strings"
	"testing"
)

// TestParseRecoversControlsOfAFormNestedInTable covers a form that the HTML
// parser reparents when it sits inside table markup: the tree form keeps its
// action but loses its controls, which used to produce an empty form POST and
// leave no parameter for active checks.
func TestParseRecoversControlsOfAFormNestedInTable(t *testing.T) {
	const document = `<html><body>
<table width="300" border="0" align="center" cellpadding="0" cellspacing="1" bgcolor="#CCCCCC">
<tr><form name="form1" method="post" action="checklogin.php"><td><table width="100%" border="0">
<tr><td width="78">Username</td><td width="6">:</td><td align="right" width=194">
<input name="myusername" type="text" id="myusername"></td></tr>
<tr><td>Password</td><td>:</td><td align="right">
<input name="mypassword" type="password" id="mypassword"></td></tr>
<tr><td>&nbsp;</td><td>&nbsp;</td><td align="right"><input type="submit" name="Submit" value="Login"></td></tr>
</table></td></form></tr></table></body></html>`

	base, err := url.Parse("http://10.22.121.23/")
	if err != nil {
		t.Fatal(err)
	}
	page, err := Parse(document, base, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Forms) != 1 {
		t.Fatalf("forms = %d, want 1", len(page.Forms))
	}
	names := map[string]bool{}
	for _, field := range page.Forms[0].Fields {
		names[field.Name] = true
	}
	for _, name := range []string{"myusername", "mypassword", "Submit"} {
		if !names[name] {
			t.Errorf("form field %q was lost: %+v", name, page.Forms[0].Fields)
		}
	}

	requests := FormRequests(page.Forms[0], base)
	if len(requests) != 1 {
		t.Fatalf("requests = %d, want 1", len(requests))
	}
	body := string(requests[0].Body)
	for _, part := range []string{"myusername=", "mypassword=", "Submit="} {
		if !strings.Contains(body, part) {
			t.Errorf("form body %q does not carry %q", body, part)
		}
	}
}

func TestTakeSourceFormDoesNotBorrowAnUnrelatedForm(t *testing.T) {
	forms := []Form{{Action: "expected", Method: "POST", Fields: []Field{{Name: "x"}}}}
	used := make([]bool, len(forms))
	if _, ok := takeSourceForm(forms, used, "other", "POST"); ok {
		t.Fatal("an unrelated source form was borrowed")
	}
	if used[0] {
		t.Fatal("an unrelated source form was consumed")
	}
}

func TestParseRecoversSelectedOptionFromNestedForm(t *testing.T) {
	const document = `<table><tr><form method="post" action="filter.php"><td>
<select name="sort"><option value="asc">Asc</option><option value="desc" selected>Desc</option></select>
<input name="q"></td></form></tr></table>`
	base, err := url.Parse("http://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	page, err := Parse(document, base, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Forms) != 1 {
		t.Fatalf("forms = %d, want 1", len(page.Forms))
	}
	values := map[string]string{}
	for _, field := range page.Forms[0].Fields {
		values[field.Name] = field.Value
	}
	if values["sort"] != "desc" {
		t.Fatalf("sort = %q, want the selected option %q (fields %+v)", values["sort"], "desc", page.Forms[0].Fields)
	}
}

func TestParseRecoversOptionWithoutEndTag(t *testing.T) {
	const document = `<table><tr><form method="post" action="filter.php"><td>
<select name="sort"><option value="asc">Asc<option value="desc" selected>Desc</select>
<input name="q"></td></form></tr></table>`
	base, err := url.Parse("http://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	page, err := Parse(document, base, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Forms) != 1 {
		t.Fatalf("forms = %d, want 1", len(page.Forms))
	}
	for _, field := range page.Forms[0].Fields {
		if field.Name == "sort" {
			if field.Value != "desc" {
				t.Fatalf("sort = %q, want selected option %q", field.Value, "desc")
			}
			return
		}
	}
	t.Fatalf("sort field missing: %+v", page.Forms[0].Fields)
}

func TestParseRecoversUnclosedSelectAtFormEnd(t *testing.T) {
	const document = `<table><tr><form method="post" action="filter.php"><td>
<select name="sort"><option value="asc" selected>A</form></tr></table>`
	base, err := url.Parse("http://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	page, err := Parse(document, base, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Forms) != 1 {
		t.Fatalf("forms = %d, want 1", len(page.Forms))
	}
	for _, field := range page.Forms[0].Fields {
		if field.Name == "sort" {
			if field.Value != "asc" {
				t.Fatalf("sort = %q, want selected option %q", field.Value, "asc")
			}
			return
		}
	}
	t.Fatalf("sort field missing: %+v", page.Forms[0].Fields)
}
