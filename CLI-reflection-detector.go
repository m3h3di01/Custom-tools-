package main

import (
    "bufio"
    "bytes"
    "context"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "os/signal"
    "strings"
    "sync"
    "syscall"
    "time"
)

const maxBodySize = 10 * 1024 * 1024

type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ", ") }
func (s *stringSlice) Set(v string) error {
    *s = append(*s, v)
    return nil
}

// paramInfo tracks one query parameter: its original value and the
// indexed marker we replaced it with.
type paramInfo struct {
    Name        string
    OrigValue   string
    MarkerValue string
}

// paramReflection is a per-parameter positive result.
type paramReflection struct {
    Param string `json:"param"`
    Count int    `json:"count"`
}

// finding is the top-level output structure.
type finding struct {
    URL         string            `json:"url"`
    Reflections []paramReflection `json:"reflections"`
}

func main() {
    var (
        marker  = flag.String("marker", "", "Custom reflection marker (required)")
        workers = flag.Int("c", 50, "Number of concurrent workers")
        timeout = flag.Duration("timeout", 10*time.Second, "HTTP timeout")
        follow  = flag.Bool("follow", false, "Follow redirects")
        proxy   = flag.String("proxy", "", "HTTP/SOCKS proxy URL")
        silent  = flag.Bool("silent", false, "Output findings only (no status messages)")
        jsonOut = flag.Bool("json", false, "Output results as JSON lines")
        headers stringSlice
    )
    flag.Var(&headers, "H", "Custom header in 'Key: Value' format (repeatable)")
    flag.Parse()

    if *marker == "" {
        fmt.Fprintln(os.Stderr, "Error: -marker is required")
        flag.Usage()
        os.Exit(1)
    }

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
    go func() {
        <-sigCh
        if !*silent {
            fmt.Fprintln(os.Stderr, "\n[!] Interrupt received, draining workers...")
        }
        cancel()
    }()

    transport := &http.Transport{
        MaxIdleConns:        1000,
        MaxIdleConnsPerHost: 100,
        MaxConnsPerHost:     100,
        IdleConnTimeout:     90 * time.Second,
        DisableKeepAlives:   false,
    }

    if *proxy != "" {
        pu, err := url.Parse(*proxy)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error: invalid proxy URL: %v\n", err)
            os.Exit(1)
        }
        transport.Proxy = http.ProxyURL(pu)
    }

    client := &http.Client{
        Transport: transport,
        Timeout:   *timeout,
    }

    if !*follow {
        client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        }
    }

    customHeaders := make(http.Header)
    for _, h := range headers {
        parts := strings.SplitN(h, ":", 2)
        if len(parts) != 2 {
            fmt.Fprintf(os.Stderr, "Error: invalid header %q (expected 'Key: Value')\n", h)
            os.Exit(1)
        }
        customHeaders.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
    }

    if !*silent {
        fmt.Fprintf(os.Stderr,
            "[*] reflectscan started | workers=%d timeout=%s marker=%s\n",
            *workers, *timeout, *marker,
        )
    }

    urlCh := make(chan string, *workers*4)

    var wg sync.WaitGroup
    for i := 0; i < *workers; i++ {
        wg.Add(1)
        go worker(ctx, client, *marker, customHeaders, urlCh, *jsonOut, &wg)
    }

    go func() {
        defer close(urlCh)

        scanner := bufio.NewScanner(os.Stdin)
        scanner.Buffer(make([]byte, 4096), 1024*1024)

        for scanner.Scan() {
            line := strings.TrimSpace(scanner.Text())
            if line == "" {
                continue
            }
            select {
            case urlCh <- line:
            case <-ctx.Done():
                return
            }
        }

        if err := scanner.Err(); err != nil && !*silent {
            fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
        }
    }()

    wg.Wait()

    if !*silent {
        fmt.Fprintln(os.Stderr, "[*] reflectscan finished")
    }
}

func worker(
    ctx context.Context,
    client *http.Client,
    marker string,
    customHeaders http.Header,
    urlCh <-chan string,
    jsonOut bool,
    wg *sync.WaitGroup,
) {
    defer wg.Done()

    pool := sync.Pool{
        New: func() interface{} { return new(bytes.Buffer) },
    }

    for rawURL := range urlCh {
        select {
        case <-ctx.Done():
            return
        default:
        }

        // Build the probe URL with indexed markers per param.
        modifiedURL, params, err := replaceParams(rawURL, marker)
        if err != nil || len(params) == 0 {
            continue
        }

        req, err := http.NewRequestWithContext(ctx, http.MethodGet, modifiedURL, nil)
        if err != nil {
            continue
        }

        for k, v := range customHeaders {
            req.Header[k] = v
        }
        if req.Header.Get("User-Agent") == "" {
            req.Header.Set("User-Agent", "reflectscan/1.0")
        }

        resp, err := client.Do(req)
        if err != nil {
            continue
        }

        buf := pool.Get().(*bytes.Buffer)
        buf.Reset()

        _, err = buf.ReadFrom(io.LimitReader(resp.Body, maxBodySize))
        resp.Body.Close()
        if err != nil {
            pool.Put(buf)
            continue
        }

        body := buf.Bytes()

        // Check each parameter's marker individually.
        var reflected []paramReflection
        reflectedSet := make(map[string]bool)

        for _, pi := range params {
            count := countMarkerExact(body, pi.MarkerValue)
            if count > 0 {
                reflected = append(reflected, paramReflection{
                    Param: pi.Name,
                    Count: count,
                })
                reflectedSet[pi.MarkerValue] = true
            }
        }

        if len(reflected) > 0 {
            // Reconstruct URL: marker values only for reflected params,
            // original values for everything else.
            outputURL := buildOutputURL(rawURL, params, reflectedSet)

            if jsonOut {
                jb, _ := json.Marshal(finding{URL: outputURL, Reflections: reflected})
                fmt.Println(string(jb))
            } else {
                var parts []string
                for _, r := range reflected {
                    parts = append(parts, fmt.Sprintf("%s:%d", r.Param, r.Count))
                }
                fmt.Printf("%s\t%s\n", outputURL, strings.Join(parts, ", "))
            }
        }

        pool.Put(buf)
    }
}

// countMarkerExact counts occurrences of marker in body, but skips a match
// when the next byte is an ASCII digit.  This prevents false positives
// caused by prefix overlap between indexed markers:
//
//      marker  = "m3h3di04"
//      marker1 = "m3h3di041"   ← marker is a prefix of marker1
//
// Without this guard, a reflection of marker1 would also increment the
// count for marker.
func countMarkerExact(body []byte, marker string) int {
    markerBytes := []byte(marker)
    mLen := len(markerBytes)
    count := 0
    start := 0

    for {
        idx := bytes.Index(body[start:], markerBytes)
        if idx == -1 {
            break
        }
        absIdx := start + idx
        afterIdx := absIdx + mLen

        // If the byte right after this match is a digit, this occurrence
        // is a prefix of a longer indexed marker — skip it.
        if afterIdx < len(body) && body[afterIdx] >= '0' && body[afterIdx] <= '9' {
            start = absIdx + 1
            continue
        }

        count++
        start = absIdx + mLen
    }

    return count
}

// replaceParams assigns an indexed marker to each query parameter value:
//
//      ?id=1&name=x&addr=y
//       → id=m3h3di04 & name=m3h3di041 & addr=m3h3di042
//
// First param gets the bare marker, each subsequent param gets marker+N.
func replaceParams(rawURL, marker string) (string, []paramInfo, error) {
    u, err := url.Parse(rawURL)
    if err != nil {
        return "", nil, err
    }

    if u.RawQuery == "" {
        return u.String(), nil, nil
    }

    pairs := strings.Split(u.RawQuery, "&")
    var b strings.Builder
    b.Grow(len(u.RawQuery) + (len(marker)+3)*len(pairs))

    params := make([]paramInfo, 0, len(pairs))
    paramIdx := 0

    for i, pair := range pairs {
        if i > 0 {
            b.WriteByte('&')
        }
        if eq := strings.IndexByte(pair, '='); eq != -1 {
            name := pair[:eq]
            origValue := pair[eq+1:]

            var markerVal string
            if paramIdx == 0 {
                markerVal = marker
            } else {
                markerVal = fmt.Sprintf("%s%d", marker, paramIdx)
            }

            b.WriteString(name)
            b.WriteByte('=')
            b.WriteString(markerVal)

            params = append(params, paramInfo{
                Name:        name,
                OrigValue:   origValue,
                MarkerValue: markerVal,
            })
            paramIdx++
        } else {
            b.WriteString(pair)
        }
    }

    u.RawQuery = b.String()
    return u.String(), params, nil
}

// buildOutputURL reconstructs the URL keeping original values for
// non-reflected params and marker values for reflected params.
//
// Example output when only name and address reflect:
//
//      domain.com/?id=1&name=m3h3di041&address=m3h3di042
func buildOutputURL(rawURL string, params []paramInfo, reflectedSet map[string]bool) string {
    u, err := url.Parse(rawURL)
    if err != nil {
        return rawURL
    }

    if u.RawQuery == "" {
        return u.String()
    }

    pairs := strings.Split(u.RawQuery, "&")
    var b strings.Builder

    paramIdx := 0
    for i, pair := range pairs {
        if i > 0 {
            b.WriteByte('&')
        }
        if eq := strings.IndexByte(pair, '='); eq != -1 {
            b.WriteString(pair[:eq+1]) // key + "="

            if paramIdx < len(params) {
                if reflectedSet[params[paramIdx].MarkerValue] {
                    b.WriteString(params[paramIdx].MarkerValue)
                } else {
                    b.WriteString(params[paramIdx].OrigValue)
                }
                paramIdx++
            } else {
                b.WriteString(pair[eq+1:])
            }
        } else {
            b.WriteString(pair)
        }
    }

    u.RawQuery = b.String()
    return u.String()
}
