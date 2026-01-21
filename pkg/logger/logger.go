package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
)

// Component identifiers for color-coded logging
type Component string

const (
	ComponentSPIREServer Component = "SPIRE-SERVER"
	ComponentSPIREAgent  Component = "SPIRE-AGENT"
	ComponentUserService Component = "USER-SERVICE"
	ComponentAgentSvc    Component = "AGENT-SERVICE"
	ComponentDocService  Component = "DOC-SERVICE"
	ComponentOPAService  Component = "OPA-SERVICE"
	ComponentDashboard   Component = "DASHBOARD"
	ComponentMTLS        Component = "mTLS"
	ComponentOPAQuery    Component = "OPA-QUERY"
	ComponentOPAEval     Component = "OPA-EVAL"
	ComponentOPADecision Component = "OPA-DECISION"
)

// ANSI color codes
const (
	colorReset   = "\033[0m"
	colorGreen   = "\033[32m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorYellow  = "\033[33m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"
	colorRed     = "\033[31m"
	colorOrange  = "\033[38;5;208m"
)

// componentColors maps components to their display colors
var componentColors = map[Component]string{
	ComponentSPIREServer: colorGreen,
	ComponentSPIREAgent:  colorGreen,
	ComponentUserService: colorBlue,
	ComponentAgentSvc:    colorMagenta,
	ComponentDocService:  colorYellow,
	ComponentOPAService:  colorCyan,
	ComponentDashboard:   colorWhite,
	ComponentMTLS:        colorYellow,
	ComponentOPAQuery:    colorOrange,
	ComponentOPAEval:     colorOrange,
	ComponentOPADecision: colorGreen,
}

// Direction indicates the flow of a request
type Direction string

const (
	DirectionOutgoing Direction = "->"
	DirectionIncoming Direction = "<-"
	DirectionNone     Direction = ""
)

// ColorHandler is a custom slog handler that adds color-coded component output
type ColorHandler struct {
	slog.Handler
	out       io.Writer
	mu        sync.Mutex
	component Component
	useColors bool
}

// NewColorHandler creates a new color-coded handler
func NewColorHandler(out io.Writer, component Component, useColors bool) *ColorHandler {
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	return &ColorHandler{
		Handler:   slog.NewTextHandler(out, opts),
		out:       out,
		component: component,
		useColors: useColors,
	}
}

// Handle processes a log record with color-coded output
func (h *ColorHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	color := componentColors[h.component]
	if !h.useColors {
		color = ""
	}

	levelEmoji := getLevelEmoji(r.Level)
	reset := colorReset
	if !h.useColors {
		reset = ""
	}

	// Format: emoji [COMPONENT] message attrs...
	fmt.Fprintf(h.out, "%s%s [%s]%s %s", color, levelEmoji, h.component, reset, r.Message)

	// Add any attributes
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(h.out, " %s=%v", a.Key, a.Value)
		return true
	})
	fmt.Fprintln(h.out)

	return nil
}

// WithAttrs returns a new handler with the given attributes
func (h *ColorHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ColorHandler{
		Handler:   h.Handler.WithAttrs(attrs),
		out:       h.out,
		component: h.component,
		useColors: h.useColors,
	}
}

// WithGroup returns a new handler with the given group
func (h *ColorHandler) WithGroup(name string) slog.Handler {
	return &ColorHandler{
		Handler:   h.Handler.WithGroup(name),
		out:       h.out,
		component: h.component,
		useColors: h.useColors,
	}
}

func getLevelEmoji(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return "\U0001F534" // Red circle
	case level >= slog.LevelWarn:
		return "\U0001F7E1" // Yellow circle
	case level >= slog.LevelInfo:
		return "\U0001F535" // Blue circle
	default:
		return "\U0001F7E3" // Purple circle
	}
}

// Logger wraps slog.Logger with component-specific functionality
type Logger struct {
	*slog.Logger
	component Component
}

// New creates a new component-specific logger
func New(component Component) *Logger {
	useColors := os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
	handler := NewColorHandler(os.Stdout, component, useColors)
	return &Logger{
		Logger:    slog.New(handler),
		component: component,
	}
}

// NewWithWriter creates a logger with a custom writer
func NewWithWriter(component Component, w io.Writer, useColors bool) *Logger {
	handler := NewColorHandler(w, component, useColors)
	return &Logger{
		Logger:    slog.New(handler),
		component: component,
	}
}

// Flow logs a directional message (incoming or outgoing)
func (l *Logger) Flow(dir Direction, msg string, args ...any) {
	prefix := ""
	if dir != DirectionNone {
		prefix = string(dir) + " "
	}
	l.Info(prefix + msg)
}

// Success logs a success message with green color
func (l *Logger) Success(msg string, args ...any) {
	l.Info("\u2705 "+msg, args...)
}

// Deny logs a denial message with red color
func (l *Logger) Deny(msg string, args ...any) {
	l.Error("\u274C "+msg, args...)
}

// Allow logs an allow decision
func (l *Logger) Allow(msg string, args ...any) {
	l.Info("\u2705 ALLOW: "+msg, args...)
}

// Section logs a section header
func (l *Logger) Section(title string) {
	l.Info("")
	l.Info("\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550")
	l.Info(" " + title)
	l.Info("\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550")
	l.Info("")
}

// Document logs document-related info
func (l *Logger) Document(docID string, msg string) {
	l.Info("\U0001F4C4 ["+docID+"] "+msg)
}

// SVID logs SVID-related info
func (l *Logger) SVID(spiffeID string, msg string) {
	l.Info("\U0001F4DC [SVID] "+msg, "spiffe_id", spiffeID)
}

// Policy logs policy evaluation info
func (l *Logger) Policy(msg string, args ...any) {
	l.Info("\U0001F4CB "+msg, args...)
}
