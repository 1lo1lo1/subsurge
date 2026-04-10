package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/1lo1lo1/subsurge/pkg/models"
)

type Format string

const (
	FormatPlain  Format = "plain"
	FormatJSON   Format = "json"
	FormatSilent Format = "silent" // only subdomains, no decoration
)

var (
	cyan   = color.New(color.FgCyan, color.Bold).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	red    = color.New(color.FgRed).SprintFunc()
	dim    = color.New(color.FgHiBlack).SprintFunc()
)

// Writer handles concurrent-safe output to stdout and an optional file.
type Writer struct {
	mu       sync.Mutex
	format   Format
	outFile  io.WriteCloser
	jsonBuf  []*models.Result
	noColor  bool
	silent   bool
	verbose  bool
}

// New creates a Writer. outPath="" means stdout only.
func New(format Format, outPath string, noColor, silent, verbose bool) (*Writer, error) {
	w := &Writer{
		format:  format,
		noColor: noColor,
		silent:  silent,
		verbose: verbose,
	}
	if noColor {
		color.NoColor = true
	}
	if outPath != "" {
		f, err := os.Create(outPath)
		if err != nil {
			return nil, fmt.Errorf("creating output file: %w", err)
		}
		w.outFile = f
	}
	return w, nil
}

// Banner prints the tool banner (suppressed in silent mode or when piped).
func (w *Writer) Banner() {
	if w.silent || !isTerminal() {
		return
	}
	fmt.Fprintf(os.Stderr, "\n%s\n", cyan(`
 ____        _   ____
/ ___| _   _| |_/ ___| _   _ _ __ __ _  ___
\___ \| | | | '_ \___ \| | | | '__/ _` + "`" + ` |/ _ \
 ___) | |_| | |_) |__) | |_| | | | (_| |  __/
|____/ \__,_|_.__/____/ \__,_|_|  \__, |\___|
                                    |___/
`))
	fmt.Fprintf(os.Stderr, "  %s - Passive Subdomain Enumeration Engine\n\n",
		dim("v1.0.0  |  github.com/1lo1lo1/subsurge"))
}

// Info prints an informational message to stderr (not in silent mode).
func (w *Writer) Info(format string, args ...any) {
	if w.silent {
		return
	}
	fmt.Fprintf(os.Stderr, "[%s] %s\n", cyan("INF"), fmt.Sprintf(format, args...))
}

// Verbose prints only when --verbose is set.
func (w *Writer) Verbose(format string, args ...any) {
	if !w.verbose || w.silent {
		return
	}
	fmt.Fprintf(os.Stderr, "[%s] %s\n", dim("VRB"), fmt.Sprintf(format, args...))
}

// Warn prints a warning to stderr.
func (w *Writer) Warn(format string, args ...any) {
	if w.silent {
		return
	}
	fmt.Fprintf(os.Stderr, "[%s] %s\n", yellow("WRN"), fmt.Sprintf(format, args...))
}

// Error prints an error to stderr.
func (w *Writer) Error(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[%s] %s\n", red("ERR"), fmt.Sprintf(format, args...))
}

// Write outputs a single result.
func (w *Writer) Write(r *models.Result) {
	w.mu.Lock()
	defer w.mu.Unlock()

	switch w.format {
	case FormatJSON:
		w.jsonBuf = append(w.jsonBuf, r)
		// Also stream plain to stdout so pipelines work
		fmt.Println(r.Domain)
	case FormatPlain:
		if w.silent || !isTerminal() {
			fmt.Println(r.Domain)
		} else {
			fmt.Printf("[%s] %s\n", dim(r.Source), green(r.Domain))
		}
	case FormatSilent:
		fmt.Println(r.Domain)
	}

	if w.outFile != nil && w.format != FormatJSON {
		fmt.Fprintln(w.outFile, r.Domain)
	}
}

// Flush finalises output (writes JSON file if needed).
func (w *Writer) Flush(stats *models.Stats) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.format == FormatJSON && w.outFile != nil {
		enc := json.NewEncoder(w.outFile)
		enc.SetIndent("", "  ")
		if err := enc.Encode(w.jsonBuf); err != nil {
			return err
		}
	}

	if stats != nil && !w.silent && isTerminal() {
		fmt.Fprintf(os.Stderr, "\n[%s] Found %s unique subdomains across %s sources in %s\n",
			cyan("INF"),
			green(fmt.Sprintf("%d", stats.Unique)),
			yellow(fmt.Sprintf("%d", len(stats.BySource))),
			dim(stats.Duration.Round(time.Millisecond).String()),
		)
		if stats.Filtered > 0 {
			fmt.Fprintf(os.Stderr, "[%s] Filtered %d wildcard/invalid results\n",
				dim("INF"), stats.Filtered)
		}
	}

	if w.outFile != nil {
		return w.outFile.Close()
	}
	return nil
}

// isTerminal returns true when stdout is a real TTY.
func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
