package main

import (
    "bufio"
    "crypto/rand"
    "crypto/tls"
    "encoding/hex"
    "fmt"
    "io"
    "net"
    "net/http"
    "net/url"
    "os"
    "regexp"
    "strings"
    "sync"
    "time"
)

const (
    workerCount          = 40
    defaultUA            = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    maxReflectionZoneLen = 2000
)

var testChars = []string{"<", ">", "\"", "'", "\\", ";", "(", ")", "{", "}", "=", "/", "|", "!", "`", ":"}

var charMarkers = []string{"q1", "w2", "e3", "r4", "t5", "y6", "u7", "i8", "o9", "p0", "a1", "s2", "d3", "f4", "g5", "h6"}

var encodings = map[string][]string{
    "<":  {"&lt;", "&LT;", "&#60;", "&#x3c;", "&#x3C;", "%3C", "%3c", "\\x3c", "\\x3C", "\\u003c"},
    ">":  {"&gt;", "&GT;", "&#62;", "&#x3e;", "&#x3E;", "%3E", "%3e", "\\x3e", "\\x3E", "\\u003e"},
    "\"": {"&quot;", "&#34;", "&#x22;", "%22", "\\x22", "\\\"", "\\u0022"},
    "'":  {"&#39;", "&apos;", "&#x27;", "%27", "\\x27", "\\'", "\\u0027"},
    "\\": {"&#92;", "%5C", "%5c", "\\\\"},
    ";":  {"&#59;", "%3B", "%3b", "\\x3b", "\\u003b"},
    "(":  {"&#40;", "%28", "\\x28", "\\u0028"},
    ")":  {"&#41;", "%29", "\\x29", "\\u0029"},
    "{":  {"&#123;", "%7B", "%7b", "\\x7b", "\\u007b"},
    "}":  {"&#125;", "%7D", "%7d", "\\x7d", "\\u007d"},
    "=":  {"&#61;", "%3D", "%3d", "\\x3d", "\\u003d"},
    "/":  {"&#47;", "%2F", "%2f", "\\x2f", "\\u002f"},
    "|":  {"&#124;", "%7C", "%7c", "\\x7c", "\\u007c"},
    "!":  {"&#33;", "%21", "\\x21", "\\u0021"},
    "`":  {"&#96;", "%60", "\\x60", "\\u0060"},
    ":":  {"&#58;", "%3A", "%3a", "\\x3a", "\\u003a"},
}

type paramCheck struct {
    url    string
    param  string
    canary string
}

type charResult struct {
    char      string
    status    string
    encodedAs string
    reflected bool
}

type singleReflection struct {
    Index       int
    Context     string
    Snippet     string
    CharResults map[string]charResult
}

type analysisResult struct {
    url         string
    param       string
    TotalCount  int
    Reflections []singleReflection
}

var transport = &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    DialContext: (&net.Dialer{
        Timeout:   30 * time.Second,
        KeepAlive: time.Second,
        DualStack: true,
    }).DialContext,
    ForceAttemptHTTP2: true,
}

var httpClient = &http.Client{
    Transport: transport,
    Timeout:   60 * time.Second,
    // CheckRedirect is nil (Go default): follow up to 10 redirects.
    // This matches the public Python kxss which uses
    // requests.get(allow_redirects=True).
}

func main() {
    if err := run(os.Stdin, os.Stdout, os.Stderr); err != nil {
        fmt.Fprintf(os.Stderr, "%s\n", err)
        os.Exit(1)
    }
}

func run(in io.Reader, out io.Writer, errOut io.Writer) error {
    sc := bufio.NewScanner(in)
    sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

    initialChecks := make(chan paramCheck, workerCount)

    // FIX 1: Replace checkReflected with direct param enumeration.
    // checkReflected caused false negatives on pages that redirect (302)
    // or don't reflect the original param value in the initial response
    // (e.g., search forms). Now every param gets the definitive canary
    // test in the next stage — zero false negatives.
    paramExtract := makePool(initialChecks, func(c paramCheck, output chan paramCheck) {
        u, err := url.Parse(c.url)
        if err != nil {
            return
        }
        seen := make(map[string]bool)
        for param := range u.Query() {
            if !seen[param] {
                seen[param] = true
                output <- paramCheck{url: c.url, param: param}
            }
        }
    })

    canaryChecks := makePool(paramExtract, func(c paramCheck, output chan paramCheck) {
        canary := generateCanary()
        reflected, err := checkAppend(c.url, c.param, canary)
        if err != nil {
            fmt.Fprintf(errOut, "[-] %s [%s]: %s\n", c.url, c.param, err)
            return
        }
        if reflected {
            output <- paramCheck{url: c.url, param: c.param, canary: canary}
        }
    })

    done := makePool(canaryChecks, func(c paramCheck, output chan paramCheck) {
        result, err := analyzeParam(c.url, c.param, c.canary, errOut)
        if err != nil {
            fmt.Fprintf(errOut, "[-] %s [%s]: %s\n", c.url, c.param, err)
            return
        }
        if result.TotalCount > 0 {
            printResult(out, result)
        }
    })

    for sc.Scan() {
        targetURL := strings.TrimSpace(sc.Text())
        if targetURL == "" || !strings.HasPrefix(targetURL, "http") {
            continue
        }
        initialChecks <- paramCheck{url: targetURL}
    }

    close(initialChecks)
    <-done
    return sc.Err()
}

func generateCanary() string {
    b := make([]byte, 6)
    _, err := rand.Read(b)
    if err != nil {
        return "fb8c1a9e2d47"
    }
    return hex.EncodeToString(b)
}

func buildCharPayload(canary string) string {
    var sb strings.Builder
    sb.WriteString(canary)
    for i, char := range testChars {
        sb.WriteString(charMarkers[i])
        sb.WriteString(char)
    }
    return sb.String()
}

func analyzeParam(targetURL, param, canary string, errOut io.Writer) (*analysisResult, error) {
    payload := buildCharPayload(canary)

    body, err := sendRequest(targetURL, param, payload)
    if err != nil {
        return nil, err
    }

    result := &analysisResult{
        url:         targetURL,
        param:       param,
        TotalCount:  strings.Count(body, canary),
        Reflections: make([]singleReflection, 0),
    }

    if result.TotalCount == 0 {
        return result, nil
    }

    searchFrom := 0
    for {
        idx := strings.Index(body[searchFrom:], canary)
        if idx == -1 {
            break
        }
        absIdx := searchFrom + idx
        searchFrom = absIdx + len(canary)

        payloadStart := absIdx + len(canary)
        remainingBody := body[payloadStart:]

        nextCanaryOffset := strings.Index(remainingBody, canary)

        var isolatedPayload string
        if nextCanaryOffset != -1 {
            isolatedPayload = remainingBody[:nextCanaryOffset]
        } else if len(remainingBody) > maxReflectionZoneLen {
            isolatedPayload = remainingBody[:maxReflectionZoneLen]
        } else {
            isolatedPayload = remainingBody
        }

        ref := determineContext(body, absIdx, len(canary))

        ref.Index = len(result.Reflections) + 1
        ref.CharResults = make(map[string]charResult)

        for i, char := range testChars {
            marker := charMarkers[i]
            ref.CharResults[char] = analyzeIsolatedCharFate(isolatedPayload, char, marker)
        }

        result.Reflections = append(result.Reflections, ref)
    }

    result.Reflections = deduplicateReflections(result.Reflections)

    return result, nil
}

func analyzeIsolatedCharFate(payload, char, marker string) charResult {
    cr := charResult{char: char, status: "removed"}

    if strings.Contains(payload, marker+char) {
        cr.status = "unfiltered"
        cr.encodedAs = char
        cr.reflected = true
        return cr
    }

    if encs, ok := encodings[char]; ok {
        for _, enc := range encs {
            if strings.Contains(payload, marker+enc) {
                cr.status = classifyEncoding(enc)
                cr.encodedAs = enc
                cr.reflected = true
                return cr
            }
        }
    }

    if strings.Contains(payload, marker) {
        cr.status = "removed"
        return cr
    }

    return cr
}

func deduplicateReflections(refs []singleReflection) []singleReflection {
    seen := make(map[string]bool)
    out := make([]singleReflection, 0)

    for _, r := range refs {
        sig := r.Context + "|"
        for _, c := range testChars {
            cr := r.CharResults[c]
            sig += fmt.Sprintf("%s:%s:%s;", c, cr.status, cr.encodedAs)
        }

        if !seen[sig] {
            seen[sig] = true
            out = append(out, r)
        }
    }
    return out
}

func classifyEncoding(enc string) string {
    if strings.HasPrefix(enc, "\\u") || strings.HasPrefix(enc, "\\U") {
        return "js_unicode"
    }
    if strings.HasPrefix(enc, "\\x") || strings.HasPrefix(enc, "\\X") {
        return "js_hex"
    }
    if strings.HasPrefix(enc, "\\") && len(enc) >= 2 {
        return "js_escaped"
    }
    if strings.HasPrefix(enc, "&#x") || strings.HasPrefix(enc, "&#X") {
        return "hex_entity"
    }
    if strings.HasPrefix(enc, "&#") {
        return "numeric_entity"
    }
    if strings.HasPrefix(enc, "&") && strings.Contains(enc, ";") {
        return "html_entity"
    }
    if strings.HasPrefix(enc, "%") {
        return "url_encoded"
    }
    return "encoded"
}

func determineContext(body string, canaryIdx, canaryLen int) singleReflection {
    rc := singleReflection{}

    snippetStart := canaryIdx - 60
    if snippetStart < 0 {
        snippetStart = 0
    }
    snippetEnd := canaryIdx + canaryLen + 60
    if snippetEnd > len(body) {
        snippetEnd = len(body)
    }
    rawSnippet := body[snippetStart:snippetEnd]
    rc.Snippet = sanitizeForOutput(rawSnippet)

    before := body[:canaryIdx]
    lowerBefore := strings.ToLower(before)

    if scriptCtx := detectScriptContext(lowerBefore, body[canaryIdx:]); scriptCtx != "" {
        rc.Context = scriptCtx
        return rc
    }

    if isInTagContext(lowerBefore, "style") {
        rc.Context = "style"
        return rc
    }

    if isInHTMLComment(lowerBefore) {
        rc.Context = "html_comment"
        return rc
    }

    if attrCtx := detectAttributeContext(before); attrCtx != "" {
        rc.Context = attrCtx
        return rc
    }

    if isInTagBody(lowerBefore) {
        rc.Context = "html_tag"
        return rc
    }

    rc.Context = "html_body"
    return rc
}

func detectScriptContext(lowerBefore, afterCanary string) string {
    lastScriptOpen := strings.LastIndex(lowerBefore, "<script")
    if lastScriptOpen == -1 {
        return ""
    }

    afterOpen := lowerBefore[lastScriptOpen:]
    gtPos := strings.Index(afterOpen, ">")
    if gtPos == -1 {
        return ""
    }

    contentAfterGT := afterOpen[gtPos+1:]
    if strings.Contains(contentAfterGT, "</script") {
        return ""
    }

    if strType := detectJSStringContext(lowerBefore); strType != "" {
        return strType
    }

    return "script"
}

func detectJSStringContext(lowerBefore string) string {
    singleOpen := hasUnclosedQuote(lowerBefore, "'")
    doubleOpen := hasUnclosedQuote(lowerBefore, "\"")
    templateOpen := hasUnclosedQuote(lowerBefore, "`")

    if templateOpen {
        return "script_template"
    }
    if doubleOpen {
        return "script_string_double"
    }
    if singleOpen {
        return "script_string_single"
    }
    return ""
}

func hasUnclosedQuote(s, quote string) bool {
    count := 0
    escaped := false
    inBlockComment := false
    inLineComment := false

    for i := 0; i < len(s); i++ {
        c := s[i]

        if inLineComment {
            if c == '\n' {
                inLineComment = false
            }
            continue
        }

        if inBlockComment {
            if i > 0 && s[i-1] == '*' && c == '/' {
                inBlockComment = false
            }
            continue
        }

        if escaped {
            escaped = false
            continue
        }

        if c == '\\' {
            escaped = true
            continue
        }

        if c == '/' && i+1 < len(s) && s[i+1] == '/' {
            inLineComment = true
            continue
        }

        if c == '/' && i+1 < len(s) && s[i+1] == '*' {
            inBlockComment = true
            continue
        }

        if byte(c) == byte(quote[0]) {
            count++
        }
    }

    return count%2 == 1
}

func isInTagContext(lowerBefore, tagName string) bool {
    openTag := "<" + tagName
    lastOpen := strings.LastIndex(lowerBefore, openTag)
    if lastOpen == -1 {
        return false
    }

    afterOpen := lowerBefore[lastOpen:]
    gtPos := strings.Index(afterOpen, ">")
    if gtPos == -1 {
        return false
    }

    closeTag := "</" + tagName
    contentAfterGT := afterOpen[gtPos+1:]
    return !strings.Contains(contentAfterGT, closeTag)
}

func isInHTMLComment(lowerBefore string) bool {
    lastComment := strings.LastIndex(lowerBefore, "<!--")
    if lastComment == -1 {
        return false
    }
    afterComment := lowerBefore[lastComment:]
    return !strings.Contains(afterComment, "-->")
}

func detectAttributeContext(before string) string {
    reDouble := regexp.MustCompile(`([\w-]+)\s*=\s*"[^"]*$`)
    reSingle := regexp.MustCompile(`([\w-]+)\s*=\s*'[^']*$`)
    reUnquoted := regexp.MustCompile(`([\w-]+)\s*=\s*[^\s"'<>=]+(?:\s+[^\s"'<>=]+)*$`)

    attrName := ""

    if m := reDouble.FindStringSubmatch(before); len(m) == 2 {
        attrName = strings.ToLower(m[1])
        return classifyAttribute(attrName, "double")
    }

    if m := reSingle.FindStringSubmatch(before); len(m) == 2 {
        attrName = strings.ToLower(m[1])
        return classifyAttribute(attrName, "single")
    }

    if m := reUnquoted.FindStringSubmatch(before); len(m) == 2 {
        attrName = strings.ToLower(m[1])
        return classifyAttribute(attrName, "unquoted")
    }

    return ""
}

func classifyAttribute(attr, quoteType string) string {
    if strings.HasPrefix(attr, "on") {
        return fmt.Sprintf("event_handler_%s_%s", quoteType, attr)
    }

    urlAttrs := map[string]bool{
        "href": true, "src": true, "action": true, "formaction": true,
        "poster": true, "background": true, "cite": true, "data": true,
        "srcdoc": true, "codebase": true, "manifest": true, "ping": true,
        "dynsrc": true, "lowsrc": true,
    }
    if urlAttrs[attr] {
        return fmt.Sprintf("url_attr_%s_%s", quoteType, attr)
    }

    if attr == "srcdoc" {
        return fmt.Sprintf("html_attr_%s_%s", quoteType, attr)
    }

    return fmt.Sprintf("attr_%s_%s", quoteType, attr)
}

func isInTagBody(lowerBefore string) bool {
    lastOpen := strings.LastIndex(lowerBefore, "<")
    if lastOpen == -1 {
        return false
    }
    afterOpen := lowerBefore[lastOpen:]
    if strings.Contains(afterOpen, ">") {
        return false
    }
    return regexp.MustCompile(`^<[a-zA-Z/!][^>]*$`).MatchString(afterOpen)
}

func sanitizeForOutput(s string) string {
    s = strings.ReplaceAll(s, "\n", "\\n")
    s = strings.ReplaceAll(s, "\r", "\\r")
    s = strings.ReplaceAll(s, "\t", "\\t")
    if len(s) > 120 {
        s = s[:60] + "..." + s[len(s)-57:]
    }
    return s
}

func sendRequest(targetURL, param, payload string) (string, error) {
    u, err := url.Parse(targetURL)
    if err != nil {
        return "", fmt.Errorf("parse url: %w", err)
    }

    qs := u.Query()
    origVal := qs.Get(param)
    qs.Set(param, origVal+payload)
    u.RawQuery = qs.Encode()

    req, err := http.NewRequest("GET", u.String(), nil)
    if err != nil {
        return "", fmt.Errorf("create request: %w", err)
    }
    req.Header.Set("User-Agent", defaultUA)
    req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    req.Header.Set("Accept-Language", "en-US,en;q=0.5")

    resp, err := httpClient.Do(req)
    if err != nil {
        return "", fmt.Errorf("send request: %w", err)
    }
    defer resp.Body.Close()

    if resp.Body == nil {
        return "", fmt.Errorf("empty response body")
    }

    b, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", fmt.Errorf("read body: %w", err)
    }

    // FIX 2: Removed redirect skip. We now follow redirects (up to 10
    // hops via Go's default client), so the final response will be the
    // page that actually contains the reflection. If we still land on
    // a 3xx here it means the redirect chain exceeded 10 hops — read
    // the body anyway rather than throwing away the result.

    ct := strings.ToLower(resp.Header.Get("Content-Type"))
    if ct != "" && !strings.Contains(ct, "html") && !strings.Contains(ct, "text/plain") && !strings.Contains(ct, "text/xml") {
        return "", fmt.Errorf("non-HTML response (%s)", ct)
    }

    return string(b), nil
}

func checkAppend(targetURL, param, suffix string) (bool, error) {
    u, err := url.Parse(targetURL)
    if err != nil {
        return false, err
    }

    qs := u.Query()
    origVal := qs.Get(param)
    qs.Set(param, origVal+suffix)
    u.RawQuery = qs.Encode()

    req, err := http.NewRequest("GET", u.String(), nil)
    if err != nil {
        return false, err
    }
    req.Header.Set("User-Agent", defaultUA)

    resp, err := httpClient.Do(req)
    if err != nil {
        return false, err
    }
    defer resp.Body.Close()

    b, err := io.ReadAll(resp.Body)
    if err != nil {
        return false, err
    }

    return strings.Contains(string(b), suffix), nil
}

func printResult(out io.Writer, r *analysisResult) {
    fmt.Fprintf(out, "\n[*] %s\n", r.url)
    fmt.Fprintf(out, "    Param: %s | Reflections: %d (Unique: %d)\n", r.param, r.TotalCount, len(r.Reflections))

    for _, ref := range r.Reflections {
        var (
            unfiltered, htmlEnt, numEnt, hexEnt, urlEnc, jsHex, jsUni, jsEsc, removed []string
        )

        for _, char := range testChars {
            cr := ref.CharResults[char]
            display := displayChar(char)
            switch cr.status {
            case "unfiltered":
                unfiltered = append(unfiltered, display)
            case "html_entity":
                htmlEnt = append(htmlEnt, fmt.Sprintf("%s>%s", display, cr.encodedAs))
            case "numeric_entity":
                numEnt = append(numEnt, fmt.Sprintf("%s>%s", display, cr.encodedAs))
            case "hex_entity":
                hexEnt = append(hexEnt, fmt.Sprintf("%s>%s", display, cr.encodedAs))
            case "url_encoded":
                urlEnc = append(urlEnc, fmt.Sprintf("%s>%s", display, cr.encodedAs))
            case "js_hex":
                jsHex = append(jsHex, fmt.Sprintf("%s>%s", display, cr.encodedAs))
            case "js_unicode":
                jsUni = append(jsUni, fmt.Sprintf("%s>%s", display, cr.encodedAs))
            case "js_escaped":
                jsEsc = append(jsEsc, fmt.Sprintf("%s>%s", display, cr.encodedAs))
            case "removed":
                removed = append(removed, display)
            }
        }

        fmt.Fprintf(out, "\n    --- Reflection %d ---\n", ref.Index)
        fmt.Fprintf(out, "    Context: %s\n", ref.Context)
        fmt.Fprintf(out, "    Snippet: %s\n", ref.Snippet)
        fmt.Fprintf(out, "    Chars:\n")

        if len(unfiltered) > 0 {
            fmt.Fprintf(out, "      [+] UNFILTERED:    %s\n", strings.Join(unfiltered, " "))
        }
        if len(htmlEnt) > 0 {
            fmt.Fprintf(out, "      [=] HTML_ENTITY:   %s\n", strings.Join(htmlEnt, " "))
        }
        if len(numEnt) > 0 {
            fmt.Fprintf(out, "      [=] NUM_ENTITY:    %s\n", strings.Join(numEnt, " "))
        }
        if len(hexEnt) > 0 {
            fmt.Fprintf(out, "      [=] HEX_ENTITY:    %s\n", strings.Join(hexEnt, " "))
        }
        if len(urlEnc) > 0 {
            fmt.Fprintf(out, "      [=] URL_ENCODED:   %s\n", strings.Join(urlEnc, " "))
        }
        if len(jsHex) > 0 {
            fmt.Fprintf(out, "      [=] JS_HEX:        %s\n", strings.Join(jsHex, " "))
        }
        if len(jsUni) > 0 {
            fmt.Fprintf(out, "      [=] JS_UNICODE:    %s\n", strings.Join(jsUni, " "))
        }
        if len(jsEsc) > 0 {
            fmt.Fprintf(out, "      [=] JS_ESCAPED:    %s\n", strings.Join(jsEsc, " "))
        }
        if len(removed) > 0 {
            fmt.Fprintf(out, "      [-] REMOVED:       %s\n", strings.Join(removed, " "))
        }
    }
}

func displayChar(c string) string {
    switch c {
    case " ":
        return "[SP]"
    case "\t":
        return "[TAB]"
    case "\n":
        return "[LF]"
    case "\\":
        return "[\\]"
    default:
        return c
    }
}

type workerFunc func(paramCheck, chan paramCheck)

func makePool(input chan paramCheck, fn workerFunc) chan paramCheck {
    var wg sync.WaitGroup
    output := make(chan paramCheck)

    for i := 0; i < workerCount; i++ {
        wg.Add(1)
        go func() {
            for c := range input {
                fn(c, output)
            }
            wg.Done()
        }()
    }

    go func() {
        wg.Wait()
        close(output)
    }()

    return output
}
