// Package taint provides a minimal taint analysis engine for gosec.
// It tracks data flow from sources (user input) to sinks (dangerous functions)
// using SSA form and call graph analysis.
//
// This implementation uses only golang.org/x/tools packages which gosec
// already depends on - no external dependencies required.
//
// Inspired by:
//   - github.com/google/capslock (call graph traversal pattern)
//   - gosec issue #1160 (requirements)
package taint

import (
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/ssa"
)

// Source defines where tainted data originates.
// Format: "package/path.TypeOrFunc" or "*package/path.Type" for pointer types.
type Source struct {
	Package string // e.g., "net/http"
	Name    string // e.g., "Request" or "Get"
	Pointer bool   // true if *Type
}

// Sink defines a dangerous function that should not receive tainted data.
// Format: "(*package/path.Type).Method" or "package/path.Func"
type Sink struct {
	Package  string // e.g., "database/sql"
	Receiver string // e.g., "DB" (empty for package-level funcs)
	Method   string // e.g., "Query"
	Pointer  bool   // true if receiver is pointer
}

// Result represents a detected taint flow from source to sink.
type Result struct {
	Source   Source
	Sink     Sink
	SinkPos  token.Pos       // Position of the sink call
	Path     []*ssa.Function // Call path from entry to sink
	SinkCall *ssa.Call       // The actual sink call instruction
}

// Config holds taint analysis configuration.
type Config struct {
	Sources []Source
	Sinks   []Sink
}

// Analyzer performs taint analysis on SSA programs.
type Analyzer struct {
	config    Config
	sources   map[string]Source // keyed by full type string
	sinks     map[string]Sink   // keyed by full function string
	callGraph *callgraph.Graph
}

// New creates a new taint analyzer with the given configuration.
func New(config Config) *Analyzer {
	a := &Analyzer{
		config:  config,
		sources: make(map[string]Source),
		sinks:   make(map[string]Sink),
	}

	// Index sources for fast lookup
	for _, src := range config.Sources {
		key := src.Package + "." + src.Name
		if src.Pointer {
			key = "*" + key
		}
		a.sources[key] = src
	}

	// Index sinks for fast lookup
	for _, sink := range config.Sinks {
		key := formatSinkKey(sink)
		a.sinks[key] = sink
	}

	return a
}

// formatSinkKey creates a lookup key for a sink.
func formatSinkKey(sink Sink) string {
	if sink.Receiver == "" {
		return sink.Package + "." + sink.Method
	}
	recv := sink.Package + "." + sink.Receiver
	if sink.Pointer {
		recv = "*" + recv
	}
	return "(" + recv + ")." + sink.Method
}

// Analyze performs taint analysis on the given SSA program.
// It returns all detected taint flows from sources to sinks.
func (a *Analyzer) Analyze(prog *ssa.Program, srcFuncs []*ssa.Function) []Result {
	if len(srcFuncs) == 0 {
		return nil
	}

	// Build call graph using Class Hierarchy Analysis (CHA).
	// CHA is fast and sound (no false negatives) but may have false positives.
	// For more precision, use VTA (Variable Type Analysis) instead.
	a.callGraph = cha.CallGraph(prog)

	var results []Result

	// Find all sink calls in the program
	for _, fn := range srcFuncs {
		results = append(results, a.analyzeFunctionSinks(fn)...)
	}

	return results
}

// analyzeFunctionSinks finds sink calls in a function and traces taint.
func (a *Analyzer) analyzeFunctionSinks(fn *ssa.Function) []Result {
	if fn == nil || fn.Blocks == nil {
		return nil
	}

	var results []Result

	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			call, ok := instr.(*ssa.Call)
			if !ok {
				continue
			}

			// Check if this call is a sink
			sink, isSink := a.isSinkCall(call)
			if !isSink {
				continue
			}

			// Check if any argument is tainted
			for i, arg := range call.Call.Args {
				if a.isTainted(arg, fn, make(map[ssa.Value]bool)) {
					results = append(results, Result{
						Sink:     sink,
						SinkPos:  call.Pos(),
						SinkCall: call,
						Path:     a.buildPath(fn, call),
					})
					_ = i // arg index could be used for more detailed reporting
					break
				}
			}
		}
	}

	return results
}

// isSinkCall checks if a call instruction is a sink and returns the sink info.
func (a *Analyzer) isSinkCall(call *ssa.Call) (Sink, bool) {
	callee := call.Call.StaticCallee()
	if callee == nil {
		return Sink{}, false
	}

	key := callee.String()

	// Try direct lookup
	if sink, ok := a.sinks[key]; ok {
		return sink, true
	}

	// Try matching by parts
	for sinkKey, sink := range a.sinks {
		if strings.Contains(key, sinkKey) {
			return sink, true
		}
	}

	return Sink{}, false
}

// isTainted recursively checks if a value is tainted (originates from a source).
func (a *Analyzer) isTainted(v ssa.Value, fn *ssa.Function, visited map[ssa.Value]bool) bool {
	if v == nil {
		return false
	}

	// Prevent infinite recursion
	if visited[v] {
		return false
	}
	visited[v] = true

	// Check if this value's type is a source
	if a.isSourceType(v.Type()) {
		return true
	}

	// Trace back through SSA instructions
	switch val := v.(type) {
	case *ssa.Parameter:
		// Parameters can be tainted if the function is called with tainted args
		return a.isParameterTainted(val, fn, visited)

	case *ssa.Call:
		// Check if the call returns a tainted type
		if a.isSourceCall(val) {
			return true
		}
		// Check if any argument to this call is tainted
		for _, arg := range val.Call.Args {
			if a.isTainted(arg, fn, visited) {
				return true
			}
		}

	case *ssa.FieldAddr:
		// Field access on a tainted struct
		return a.isTainted(val.X, fn, visited)

	case *ssa.IndexAddr:
		// Index into a tainted slice/array
		return a.isTainted(val.X, fn, visited)

	case *ssa.UnOp:
		// Unary operation (like pointer dereference)
		return a.isTainted(val.X, fn, visited)

	case *ssa.BinOp:
		// Binary operation - tainted if either operand is tainted
		return a.isTainted(val.X, fn, visited) || a.isTainted(val.Y, fn, visited)

	case *ssa.Phi:
		// Phi node - tainted if any edge is tainted
		for _, edge := range val.Edges {
			if a.isTainted(edge, fn, visited) {
				return true
			}
		}

	case *ssa.Extract:
		// Extract from tuple - check the tuple
		return a.isTainted(val.Tuple, fn, visited)

	case *ssa.TypeAssert:
		// Type assertion - check the underlying value
		return a.isTainted(val.X, fn, visited)

	case *ssa.MakeInterface:
		// Interface creation - check the underlying value
		return a.isTainted(val.X, fn, visited)

	case *ssa.Slice:
		// Slice operation - check the sliced value
		return a.isTainted(val.X, fn, visited)

	case *ssa.Convert:
		// Type conversion - check the converted value
		return a.isTainted(val.X, fn, visited)

	case *ssa.ChangeType:
		// Type change - check the underlying value
		return a.isTainted(val.X, fn, visited)

	case *ssa.Alloc:
		// Allocation - check referrers for assignments
		for _, ref := range *val.Referrers() {
			if store, ok := ref.(*ssa.Store); ok {
				if a.isTainted(store.Val, fn, visited) {
					return true
				}
			}
		}

	case *ssa.Lookup:
		// Map/string lookup - check the map/string
		return a.isTainted(val.X, fn, visited)

	case *ssa.MakeSlice, *ssa.MakeMap, *ssa.MakeChan:
		// New containers are not tainted by default
		return false

	case *ssa.Const:
		// Constants are never tainted
		return false

	case *ssa.Global:
		// Global variables - check if they're a known source
		return a.isSourceType(val.Type())
	}

	return false
}

// isSourceType checks if a type matches any configured source.
func (a *Analyzer) isSourceType(t types.Type) bool {
	if t == nil {
		return false
	}

	typeStr := t.String()

	// Direct match
	if _, ok := a.sources[typeStr]; ok {
		return true
	}

	// Check underlying type for named types
	if named, ok := t.(*types.Named); ok {
		obj := named.Obj()
		if obj != nil && obj.Pkg() != nil {
			key := obj.Pkg().Path() + "." + obj.Name()
			if _, ok := a.sources[key]; ok {
				return true
			}
			// Check pointer variant
			if _, ok := a.sources["*"+key]; ok {
				return true
			}
		}
	}

	// Check pointer types
	if ptr, ok := t.(*types.Pointer); ok {
		return a.isSourceType(ptr.Elem())
	}

	return false
}

// isSourceCall checks if a call returns a value from a source function.
func (a *Analyzer) isSourceCall(call *ssa.Call) bool {
	callee := call.Call.StaticCallee()
	if callee == nil {
		return false
	}

	// Check if return type is a source
	if a.isSourceType(call.Type()) {
		return true
	}

	// Check if function itself is a source
	key := callee.String()
	for srcKey := range a.sources {
		if strings.Contains(key, srcKey) {
			return true
		}
	}

	return false
}

// isParameterTainted checks if a function parameter receives tainted data.
func (a *Analyzer) isParameterTainted(param *ssa.Parameter, fn *ssa.Function, visited map[ssa.Value]bool) bool {
	// Check if parameter type is a source
	if a.isSourceType(param.Type()) {
		return true
	}

	// Use call graph to find callers and check their arguments
	if a.callGraph == nil {
		return false
	}

	node := a.callGraph.Nodes[fn]
	if node == nil {
		return false
	}

	paramIdx := -1
	for i, p := range fn.Params {
		if p == param {
			paramIdx = i
			break
		}
	}

	if paramIdx < 0 {
		return false
	}

	// Check each caller
	for _, inEdge := range node.In {
		site := inEdge.Site
		if site == nil {
			continue
		}

		callArgs := site.Common().Args

		// Adjust for receiver
		if fn.Signature.Recv() != nil {
			paramIdx++
		}

		if paramIdx < len(callArgs) {
			if a.isTainted(callArgs[paramIdx], inEdge.Caller.Func, visited) {
				return true
			}
		}
	}

	return false
}

// buildPath constructs the call path from entry point to the sink.
func (a *Analyzer) buildPath(fn *ssa.Function, _ *ssa.Call) []*ssa.Function {
	if a.callGraph == nil {
		return []*ssa.Function{fn}
	}

	// BFS to find path from root to this function
	path := []*ssa.Function{fn}

	node := a.callGraph.Nodes[fn]
	if node == nil {
		return path
	}

	// Simple path: just trace callers up
	visited := make(map[*ssa.Function]bool)
	current := node

	for current != nil && len(current.In) > 0 {
		if visited[current.Func] {
			break
		}
		visited[current.Func] = true

		caller := current.In[0].Caller
		if caller == nil || caller.Func == nil {
			break
		}

		path = append([]*ssa.Function{caller.Func}, path...)
		current = caller
	}

	return path
}
