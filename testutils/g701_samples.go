package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG701 - SQL injection via taint analysis
var SampleCodeG701 = []CodeSample{
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	name := r.URL.Query().Get("name")
	query := "SELECT * FROM users WHERE name = '" + name + "'"
	db.Query(query)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
	"fmt"
)

func handler(db *sql.DB, r *http.Request) {
	id := r.FormValue("id")
	query := fmt.Sprintf("DELETE FROM users WHERE id = %s", id)
	db.Exec(query)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"database/sql"
)

func safeQuery(db *sql.DB) {
	// Safe - no user input
	db.Query("SELECT * FROM users")
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func preparedStatement(db *sql.DB, r *http.Request) {
	// Safe - using prepared statement
	name := r.URL.Query().Get("name")
	db.Query("SELECT * FROM users WHERE name = ?", name)
}
`}, 0, gosec.NewConfig()},

	// Field tracking test 1: Struct literal with tainted field (tests isFieldOfAllocTainted)
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

type Query struct {
	SQL string
}

func handler(db *sql.DB, r *http.Request) {
	q := &Query{SQL: r.FormValue("input")}
	db.Query(q.SQL)
}
`}, 1, gosec.NewConfig()},

	// Field tracking test 2: Function returns struct (tests isFieldTaintedViaCall)
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

type Config struct {
	Value string
}

func newConfig(v string) *Config {
	return &Config{Value: v}
}

func handler(db *sql.DB, r *http.Request) {
	cfg := newConfig(r.FormValue("input"))
	db.Query(cfg.Value)
}
`}, 1, gosec.NewConfig()},

	// Field tracking test 3: Pointer field access (tests isFieldAccessOnPointerTainted, isFieldTaintedOnValue)
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

type Query struct {
	SQL string
}

func handler(db *sql.DB, r *http.Request) {
	q := &Query{SQL: r.FormValue("input")}
	ptr := q
	db.Query((*ptr).SQL)
}
`}, 1, gosec.NewConfig()},

	// Field tracking test 4: Closure captures tainted variable (tests isFreeVarTainted)
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	userID := r.FormValue("id")
	execute := func() {
		query := "DELETE FROM users WHERE id = " + userID
		db.Exec(query)
	}
	execute()
}
`}, 1, gosec.NewConfig()},

	// Field tracking test 5: Multi-return field extraction (tests isFieldAccessTainted with Extract)
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

type Config struct {
	Value string
}

func newConfig(v string) (*Config, error) {
	return &Config{Value: v}, nil
}

func handler(db *sql.DB, r *http.Request) {
	cfg, _ := newConfig(r.FormValue("input"))
	db.Query(cfg.Value)
}
`}, 1, gosec.NewConfig()},

	// Field tracking test 6: Nested struct field access
	// Note: Current implementation doesn't track nested field paths (req.Query.SQL)
	// This test documents the limitation - should be 1 issue but detects 0
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

type Query struct {
	SQL string
}

type Request struct {
	Query *Query
}

func handler(db *sql.DB, r *http.Request) {
	req := &Request{Query: &Query{SQL: r.FormValue("input")}}
	db.Query(req.Query.SQL)
}
`}, 0, gosec.NewConfig()},

	// Field tracking test 7: Field taint through control flow merge (tests Phi nodes)
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

type Query struct {
	SQL string
}

func handler(db *sql.DB, r *http.Request) {
	var q *Query
	if r.FormValue("type") == "admin" {
		q = &Query{SQL: r.FormValue("admin_query")}
	} else {
		q = &Query{SQL: r.FormValue("user_query")}
	}
	db.Query(q.SQL)
}
`}, 1, gosec.NewConfig()},

	// Additional coverage tests for various SSA value types

	// Test 8: BinOp - Multiple string concatenations (tests BinOp taint propagation)
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	name := r.FormValue("name")
	age := r.FormValue("age")
	query := "SELECT * FROM users WHERE name = '" + name + "' AND age = " + age
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Test 9: Slice operation (tests Slice taint propagation)
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	params := []string{r.FormValue("p1"), r.FormValue("p2")}
	query := "SELECT * FROM users WHERE id = " + params[0]
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Test 10: IndexAddr - Array/slice indexing (tests IndexAddr taint propagation)
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	ids := [3]string{r.FormValue("id1"), r.FormValue("id2"), r.FormValue("id3")}
	query := "DELETE FROM users WHERE id = " + ids[1]
	db.Exec(query)
}
`}, 1, gosec.NewConfig()},

	// Test 11: Convert operation (tests Convert taint propagation)
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	input := r.FormValue("data")
	bytes := []byte(input)
	query := "INSERT INTO logs VALUES ('" + string(bytes) + "')"
	db.Exec(query)
}
`}, 1, gosec.NewConfig()},

	// Test 12: MakeInterface (tests MakeInterface taint propagation)
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
	"fmt"
)

func handler(db *sql.DB, r *http.Request) {
	var val interface{} = r.FormValue("value")
	query := fmt.Sprintf("SELECT * FROM data WHERE value = '%v'", val)
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Test 13: Extract from tuple (multi-value return) with error handling
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
	"strconv"
)

func handler(db *sql.DB, r *http.Request) {
	userID, err := strconv.Atoi(r.FormValue("id"))
	if err == nil {
		query := "SELECT * FROM users WHERE id = " + strconv.Itoa(userID)
		db.Query(query)
	}
}
`}, 1, gosec.NewConfig()},

	// Test 14: Phi node with loop (tests Phi taint propagation in loops)
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	input := r.FormValue("input")
	var result string
	for i := 0; i < 10; i++ {
		result = input + result
	}
	db.Query("SELECT * FROM data WHERE value = '" + result + "'")
}
`}, 1, gosec.NewConfig()},

	// Test 15: UnOp dereference (tests UnOp taint propagation)
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	input := r.FormValue("id")
	ptr := &input
	query := "DELETE FROM users WHERE id = " + *ptr
	db.Exec(query)
}
`}, 1, gosec.NewConfig()},

	// Test 16: ChangeType (tests ChangeType taint propagation)
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
	"unsafe"
)

func handler(db *sql.DB, r *http.Request) {
	input := r.FormValue("data")
	bytes := []byte(input)
	ptr := unsafe.Pointer(&bytes[0])
	_ = ptr
	query := "INSERT INTO logs VALUES ('" + input + "')"
	db.Exec(query)
}
`}, 1, gosec.NewConfig()},

	// Test 17: Field from Alloc with Store (tests Store instruction tracking)
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

type Data struct {
	Value string
}

func handler(db *sql.DB, r *http.Request) {
	d := &Data{}
	d.Value = r.FormValue("input")
	db.Query("SELECT * FROM items WHERE name = '" + d.Value + "'")
}
`}, 1, gosec.NewConfig()},

	// Interprocedural analysis tests (to cover valueReachableFromParams, doTaintedArgsFlowToReturn)

	// Test 18: Simple parameter flow - tainted param flows to return
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func buildQuery(userInput string) string {
	return "SELECT * FROM users WHERE name = '" + userInput + "'"
}

func handler(db *sql.DB, r *http.Request) {
	name := r.FormValue("name")
	query := buildQuery(name)
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Test 19: Parameter through variable assignment
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func processInput(input string) string {
	result := input
	return result
}

func handler(db *sql.DB, r *http.Request) {
	data := r.FormValue("data")
	processed := processInput(data)
	db.Query("DELETE FROM logs WHERE data = '" + processed + "'")
}
`}, 1, gosec.NewConfig()},

	// Test 20: Parameter through BinOp in helper function
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func formatQuery(table string, id string) string {
	return "SELECT * FROM " + table + " WHERE id = " + id
}

func handler(db *sql.DB, r *http.Request) {
	userID := r.FormValue("id")
	query := formatQuery("users", userID)
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Test 21: Parameter through Phi node (if/else in helper)
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func selectTable(isAdmin bool, userID string) string {
	var table string
	if isAdmin {
		table = "admin_" + userID
	} else {
		table = "user_" + userID
	}
	return table
}

func handler(db *sql.DB, r *http.Request) {
	id := r.FormValue("id")
	table := selectTable(false, id)
	db.Query("SELECT * FROM " + table)
}
`}, 1, gosec.NewConfig()},

	// Test 22: Parameter through struct field in helper
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

type QueryBuilder struct {
	table string
}

func newQueryBuilder(tableName string) *QueryBuilder {
	return &QueryBuilder{table: tableName}
}

func handler(db *sql.DB, r *http.Request) {
	userTable := r.FormValue("table")
	qb := newQueryBuilder(userTable)
	db.Query("SELECT * FROM " + qb.table)
}
`}, 1, gosec.NewConfig()},

	// Test 23: Parameter through slice in helper
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func getFirst(items []string) string {
	if len(items) > 0 {
		return items[0]
	}
	return ""
}

func handler(db *sql.DB, r *http.Request) {
	ids := []string{r.FormValue("id1"), r.FormValue("id2")}
	firstID := getFirst(ids)
	db.Query("DELETE FROM users WHERE id = " + firstID)
}
`}, 1, gosec.NewConfig()},

	// Test 24: Parameter through Convert in helper
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func convertToString(data []byte) string {
	return string(data)
}

func handler(db *sql.DB, r *http.Request) {
	input := r.FormValue("data")
	bytes := []byte(input)
	str := convertToString(bytes)
	db.Query("INSERT INTO logs VALUES ('" + str + "')")
}
`}, 1, gosec.NewConfig()},

	// Test 25: Parameter through Extract (multi-return) in helper
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func parseInput(input string) (string, error) {
	return input, nil
}

func handler(db *sql.DB, r *http.Request) {
	data := r.FormValue("data")
	parsed, _ := parseInput(data)
	db.Query("SELECT * FROM data WHERE value = '" + parsed + "'")
}
`}, 1, gosec.NewConfig()},

	// Test 26: Parameter through nested calls
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func innerProcess(s string) string {
	return s + "_processed"
}

func outerProcess(input string) string {
	return innerProcess(input)
}

func handler(db *sql.DB, r *http.Request) {
	userInput := r.FormValue("input")
	result := outerProcess(userInput)
	db.Query("SELECT * FROM data WHERE value = '" + result + "'")
}
`}, 1, gosec.NewConfig()},

	// Test 27: Parameter through UnOp in helper
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func derefString(ptr *string) string {
	return *ptr
}

func handler(db *sql.DB, r *http.Request) {
	input := r.FormValue("id")
	value := derefString(&input)
	db.Query("DELETE FROM users WHERE id = " + value)
}
`}, 1, gosec.NewConfig()},

	// Test 28: Parameter through MakeInterface in helper
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
	"fmt"
)

func toInterface(s string) interface{} {
	return s
}

func handler(db *sql.DB, r *http.Request) {
	input := r.FormValue("value")
	iface := toInterface(input)
	query := fmt.Sprintf("SELECT * FROM data WHERE value = '%v'", iface)
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Test 29: Parameter through FieldAddr stores in helper
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

type Config struct {
	Value string
}

func createConfig(val string) *Config {
	c := &Config{}
	c.Value = val
	return c
}

func handler(db *sql.DB, r *http.Request) {
	userVal := r.FormValue("value")
	cfg := createConfig(userVal)
	db.Query("SELECT * FROM data WHERE value = '" + cfg.Value + "'")
}
`}, 1, gosec.NewConfig()},

	// Test 30: Parameter through Call Args in helper (nested call)
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
	"strings"
)

func wrapWithQuotes(s string) string {
	return strings.ToLower(s)
}

func handler(db *sql.DB, r *http.Request) {
	input := r.FormValue("name")
	wrapped := wrapWithQuotes(input)
	db.Query("SELECT * FROM users WHERE name = '" + wrapped + "'")
}
`}, 1, gosec.NewConfig()},

	// Additional interprocedural tests for edge cases

	// Test 31: Parameter through TypeAssert in helper
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func extractString(val interface{}) string {
	if str, ok := val.(string); ok {
		return str
	}
	return ""
}

func handler(db *sql.DB, r *http.Request) {
	var data interface{} = r.FormValue("data")
	extracted := extractString(data)
	db.Query("SELECT * FROM data WHERE value = '" + extracted + "'")
}
`}, 1, gosec.NewConfig()},

	// Test 32: Parameter through map Lookup in helper
	// Note: Current implementation doesn't track taint through map values
	// Map literal with tainted value → map lookup doesn't propagate taint
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func lookupValue(m map[string]string, key string) string {
	return m[key]
}

func handler(db *sql.DB, r *http.Request) {
	userKey := r.FormValue("key")
	data := map[string]string{"user": userKey, "admin": "admin_value"}
	value := lookupValue(data, "user")
	db.Query("SELECT * FROM users WHERE id = '" + value + "'")
}
`}, 0, gosec.NewConfig()},

	// Test 33: Parameter through complex Alloc with multiple stores
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

type ComplexData struct {
	Field1 string
	Field2 string
}

func buildComplexData(input string) *ComplexData {
	d := &ComplexData{}
	d.Field1 = input
	d.Field2 = "safe"
	return d
}

func handler(db *sql.DB, r *http.Request) {
	userInput := r.FormValue("input")
	data := buildComplexData(userInput)
	db.Query("SELECT * FROM data WHERE value = '" + data.Field1 + "'")
}
`}, 1, gosec.NewConfig()},

	// Test 34: Parameter through chained Slice operations
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func sliceData(items []string) []string {
	if len(items) > 1 {
		return items[1:]
	}
	return items
}

func handler(db *sql.DB, r *http.Request) {
	inputs := []string{"safe", r.FormValue("data"), r.FormValue("data2")}
	sliced := sliceData(inputs)
	if len(sliced) > 0 {
		db.Query("SELECT * FROM data WHERE value = '" + sliced[0] + "'")
	}
}
`}, 1, gosec.NewConfig()},

	// Test 35: Parameter through IndexAddr with array
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func getArrayElement(arr [3]string, idx int) string {
	return arr[idx]
}

func handler(db *sql.DB, r *http.Request) {
	userArray := [3]string{r.FormValue("a"), r.FormValue("b"), r.FormValue("c")}
	element := getArrayElement(userArray, 1)
	db.Query("DELETE FROM users WHERE id = '" + element + "'")
}
`}, 1, gosec.NewConfig()},

	// Test 36: Parameter through nested Phi with loop
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func accumulateData(base string, count int) string {
	result := base
	for i := 0; i < count; i++ {
		if i%2 == 0 {
			result = result + "_even"
		} else {
			result = result + "_odd"
		}
	}
	return result
}

func handler(db *sql.DB, r *http.Request) {
	userInput := r.FormValue("data")
	accumulated := accumulateData(userInput, 3)
	db.Query("SELECT * FROM data WHERE value = '" + accumulated + "'")
}
`}, 1, gosec.NewConfig()},

	// Test 37: Parameter through multiple UnOp dereferences
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func doubleDeref(s string) string {
	ptr1 := &s
	ptr2 := &ptr1
	return **ptr2
}

func handler(db *sql.DB, r *http.Request) {
	input := r.FormValue("id")
	result := doubleDeref(input)
	db.Query("DELETE FROM users WHERE id = '" + result + "'")
}
`}, 1, gosec.NewConfig()},

	// Test 38: Parameter through ChangeType in helper
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
	"unsafe"
)

func unsafeConvert(s string) string {
	bytes := []byte(s)
	ptr := unsafe.Pointer(&bytes[0])
	_ = ptr
	return s
}

func handler(db *sql.DB, r *http.Request) {
	input := r.FormValue("data")
	converted := unsafeConvert(input)
	db.Query("INSERT INTO logs VALUES ('" + converted + "')")
}
`}, 1, gosec.NewConfig()},

	// Additional tests specifically for valueReachableFromParams edge cases

	// Test 39: Multiple parameters with BinOp combination
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func combineInputs(a string, b string, c string) string {
	return a + b + c
}

func handler(db *sql.DB, r *http.Request) {
	p1 := r.FormValue("p1")
	p2 := r.FormValue("p2")
	p3 := r.FormValue("p3")
	result := combineInputs(p1, p2, p3)
	db.Query("SELECT * FROM data WHERE value = '" + result + "'")
}
`}, 1, gosec.NewConfig()},

	// Test 40: Parameter through nested FieldAddr in struct
	// Note: Nested field paths (outer.Inner.Value) not fully tracked
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

type Inner struct {
	Value string
}

type Outer struct {
	Inner *Inner
}

func buildNested(val string) *Outer {
	inner := &Inner{}
	inner.Value = val
	return &Outer{Inner: inner}
}

func handler(db *sql.DB, r *http.Request) {
	input := r.FormValue("input")
	outer := buildNested(input)
	db.Query("SELECT * FROM data WHERE value = '" + outer.Inner.Value + "'")
}
`}, 0, gosec.NewConfig()},

	// Test 41: Parameter through Slice with multiple elements
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func processSlice(items []string) string {
	result := ""
	for _, item := range items {
		result = result + item
	}
	return result
}

func handler(db *sql.DB, r *http.Request) {
	data := []string{r.FormValue("a"), "safe", r.FormValue("b")}
	processed := processSlice(data)
	db.Query("SELECT * FROM data WHERE value = '" + processed + "'")
}
`}, 1, gosec.NewConfig()},

	// Test 42: Parameter through Extract with multiple returns
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func multiReturn(input string) (string, string, error) {
	return input, "safe", nil
}

func handler(db *sql.DB, r *http.Request) {
	userInput := r.FormValue("data")
	result1, result2, _ := multiReturn(userInput)
	db.Query("SELECT * FROM data WHERE v1 = '" + result1 + "' AND v2 = '" + result2 + "'")
}
`}, 1, gosec.NewConfig()},

	// Test 43: Parameter through nested Phi with multiple branches
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func conditionalProcess(input string, mode int) string {
	var result string
	switch mode {
	case 1:
		result = input + "_mode1"
	case 2:
		result = input + "_mode2"
	default:
		result = input + "_default"
	}
	return result
}

func handler(db *sql.DB, r *http.Request) {
	userInput := r.FormValue("input")
	processed := conditionalProcess(userInput, 1)
	db.Query("SELECT * FROM data WHERE value = '" + processed + "'")
}
`}, 1, gosec.NewConfig()},

	// Test 44: Parameter through Call with multiple arguments
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
	"fmt"
)

func formatMultiple(template string, args ...interface{}) string {
	return fmt.Sprintf(template, args...)
}

func handler(db *sql.DB, r *http.Request) {
	userVal := r.FormValue("value")
	formatted := formatMultiple("data=%s", userVal)
	db.Query("SELECT * FROM logs WHERE entry = '" + formatted + "'")
}
`}, 1, gosec.NewConfig()},

	// Test 45: Parameter through nested Call chains
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
	"strings"
)

func processStep1(s string) string {
	return strings.TrimSpace(s)
}

func processStep2(s string) string {
	return strings.ToLower(processStep1(s))
}

func processStep3(s string) string {
	return strings.ToUpper(processStep2(s))
}

func handler(db *sql.DB, r *http.Request) {
	input := r.FormValue("data")
	result := processStep3(input)
	db.Query("SELECT * FROM data WHERE value = '" + result + "'")
}
`}, 1, gosec.NewConfig()},

	// Test 46: Parameter through IndexAddr with dynamic index
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func getElement(arr []string, idx int) string {
	if idx >= 0 && idx < len(arr) {
		return arr[idx]
	}
	return ""
}

func handler(db *sql.DB, r *http.Request) {
	data := []string{r.FormValue("a"), r.FormValue("b"), r.FormValue("c")}
	element := getElement(data, 2)
	db.Query("DELETE FROM users WHERE id = '" + element + "'")
}
`}, 1, gosec.NewConfig()},

	// Test 47: Parameter through MakeInterface with type conversion
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
	"fmt"
)

func convertToAny(s string) interface{} {
	var result interface{} = s
	return result
}

func handler(db *sql.DB, r *http.Request) {
	input := r.FormValue("value")
	anyVal := convertToAny(input)
	query := fmt.Sprintf("SELECT * FROM data WHERE value = '%v'", anyVal)
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Test 48: Parameter through complex Alloc pattern with reassignment
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

type Container struct {
	Data string
}

func createAndUpdate(initial string, update string) *Container {
	c := &Container{Data: initial}
	c.Data = update
	return c
}

func handler(db *sql.DB, r *http.Request) {
	userInput := r.FormValue("input")
	container := createAndUpdate("safe", userInput)
	db.Query("SELECT * FROM data WHERE value = '" + container.Data + "'")
}
`}, 1, gosec.NewConfig()},

	// Minimal tests for maximum branch coverage

	// Test 49: URL sanitizer doesn't prevent SQL injection
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
	"net/url"
)

func handler(db *sql.DB, r *http.Request) {
	userInput := r.FormValue("data")
	sanitized := url.QueryEscape(userInput)
	db.Query("SELECT * FROM data WHERE value = '" + sanitized + "'")
}
`}, 1, gosec.NewConfig()},

	// Test 50: Empty/nil handling
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	query := ""
	if r != nil {
		query = "SELECT * FROM users WHERE id = " + r.FormValue("id")
	}
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Test 51: Global variable taint source
	{[]string{`
package main

import (
	"database/sql"
	"os"
)

func handler(db *sql.DB) {
	userInput := os.Getenv("USER_ID")
	db.Query("DELETE FROM users WHERE id = " + userInput)
}
`}, 1, gosec.NewConfig()},

	// Test 52: Taint through interface method
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

type Getter interface {
	Get(string) string
}

func query(db *sql.DB, g Getter) {
	id := g.Get("id")
	db.Query("SELECT * FROM users WHERE id = " + id)
}

func handler(db *sql.DB, r *http.Request) {
	query(db, r.URL.Query())
}
`}, 1, gosec.NewConfig()},

	// Test 53: Const value (safe)
	{[]string{`
package main

import "database/sql"

func handler(db *sql.DB) {
	const userID = "safe123"
	db.Query("SELECT * FROM users WHERE id = " + userID)
}
`}, 0, gosec.NewConfig()},

	// Test 54: Taint through builtin append
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	parts := []string{"SELECT * FROM users WHERE id = "}
	parts = append(parts, r.FormValue("id"))
	db.Query(parts[0] + parts[1])
}
`}, 1, gosec.NewConfig()},

	// Test 55: FreeVar returns false (closure limitation)
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func makeQuery() func(*sql.DB) {
	const id = "123"
	return func(db *sql.DB) {
		db.Query("SELECT * FROM users WHERE id = " + id)
	}
}

func handler(db *sql.DB, r *http.Request) {
	q := makeQuery()
	q(db)
}
`}, 0, gosec.NewConfig()},

	// Lookup operation (map access)
	// NOTE: Map value taint tracking not yet supported - documented limitation
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	userInputs := map[string]string{
		"query": r.FormValue("q"),
	}
	query := "SELECT * FROM users WHERE name = '" + userInputs["query"] + "'"
	db.Query(query)
}
`}, 0, gosec.NewConfig()},

	// Type assertion with tainted data
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	var data interface{} = r.FormValue("data")
	str := data.(string)
	query := "SELECT * FROM users WHERE id = '" + str + "'"
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Slice operation on tainted input
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	inputs := []string{r.FormValue("a"), r.FormValue("b")}
	subset := inputs[0:1]
	query := "SELECT * FROM users WHERE id = '" + subset[0] + "'"
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Unary operation (pointer dereference) on tainted data
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	userInput := r.FormValue("id")
	ptr := &userInput
	query := "SELECT * FROM users WHERE id = '" + *ptr + "'"
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// ChangeType operation with unsafe pointer conversion
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
	"unsafe"
)

func handler(db *sql.DB, r *http.Request) {
	userInput := r.FormValue("data")
	bytes := []byte(userInput)
	ptr := unsafe.Pointer(&bytes[0])
	str := *(*string)(ptr)
	query := "SELECT * FROM users WHERE data = '" + str + "'"
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Multi-return with conditional (Phi node)
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func getData(r *http.Request) (string, error) {
	return r.FormValue("id"), nil
}

func handler(db *sql.DB, r *http.Request) {
	var id string
	if true {
		id, _ = getData(r)
	} else {
		id = "default"
	}
	query := "SELECT * FROM users WHERE id = '" + id + "'"
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Array element access with tainted data
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	var inputs [3]string
	inputs[0] = r.FormValue("id")
	query := "SELECT * FROM users WHERE id = '" + inputs[0] + "'"
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Interface conversion with tainted data
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	userInput := r.FormValue("data")
	var iface interface{} = userInput
	str, _ := iface.(string)
	query := "SELECT * FROM users WHERE data = '" + str + "'"
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Nested type conversions with tainted data
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

type CustomString string

func handler(db *sql.DB, r *http.Request) {
	userInput := r.FormValue("id")
	custom := CustomString(userInput)
	str := string(custom)
	query := "SELECT * FROM users WHERE id = '" + str + "'"
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Conditional assignment with potential nil (Phi node)
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	var data string
	if r.Method == "POST" {
		data = r.FormValue("data")
	}
	if data != "" {
		query := "SELECT * FROM users WHERE data = '" + data + "'"
		db.Query(query)
	}
}
`}, 1, gosec.NewConfig()},

	// Global variable with tainted data
	// NOTE: Global variable taint tracking not yet supported - documented limitation
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

var globalQuery string

func handler(db *sql.DB, r *http.Request) {
	globalQuery = r.FormValue("query")
	executeQuery(db)
}

func executeQuery(db *sql.DB) {
	db.Query(globalQuery)
}
`}, 0, gosec.NewConfig()},

	// Complex Phi node - multiple branches converging
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	var id string
	switch r.Method {
	case "GET":
		id = r.URL.Query().Get("id")
	case "POST":
		id = r.FormValue("id")
	case "PUT":
		id = r.Header.Get("X-ID")
	default:
		id = "default"
	}
	query := "SELECT * FROM users WHERE id = '" + id + "'"
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Advanced interprocedural - deep call chain
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	userInput := r.FormValue("name")
	result := processLevel1(userInput)
	executeQuery(db, result)
}

func processLevel1(input string) string {
	return processLevel2(input)
}

func processLevel2(input string) string {
	return processLevel3(input)
}

func processLevel3(input string) string {
	return "SELECT * FROM users WHERE name = '" + input + "'"
}

func executeQuery(db *sql.DB, query string) {
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Interprocedural with struct field assignment
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

type QueryBuilder struct {
	Filter string
}

func handler(db *sql.DB, r *http.Request) {
	qb := &QueryBuilder{}
	setFilter(qb, r)
	executeQueryBuilder(db, qb)
}

func setFilter(qb *QueryBuilder, r *http.Request) {
	qb.Filter = r.FormValue("filter")
}

func executeQueryBuilder(db *sql.DB, qb *QueryBuilder) {
	query := "SELECT * FROM users WHERE " + qb.Filter
	db.Query(query)
}
`}, 0, gosec.NewConfig()}, // NOTE: Some advanced patterns have limitations

	// Global struct with tainted field
	// NOTE: Global variable taint tracking not yet supported - documented limitation
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

type Config struct {
	SearchTerm string
}

var appConfig Config

func handler(db *sql.DB, r *http.Request) {
	appConfig.SearchTerm = r.FormValue("search")
	search(db)
}

func search(db *sql.DB) {
	query := "SELECT * FROM products WHERE name LIKE '%" + appConfig.SearchTerm + "%'"
	db.Query(query)
}
`}, 0, gosec.NewConfig()},

	// Complex Phi with nested conditionals
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	var query string
	if r.Method == "POST" {
		if r.Header.Get("Content-Type") == "application/json" {
			query = r.FormValue("json_query")
		} else {
			query = r.FormValue("form_query")
		}
	} else {
		if r.URL.Query().Get("type") == "advanced" {
			query = r.URL.Query().Get("advanced_query")
		} else {
			query = r.URL.Query().Get("simple_query")
		}
	}
	sql := "SELECT * FROM data WHERE condition = '" + query + "'"
	db.Query(sql)
}
`}, 1, gosec.NewConfig()},

	// Interprocedural with multiple parameters
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	name := r.FormValue("name")
	email := r.FormValue("email")
	query := buildUserQuery(name, email)
	db.Query(query)
}

func buildUserQuery(name, email string) string {
	return combineFields("users", name, email)
}

func combineFields(table, field1, field2 string) string {
	return "SELECT * FROM " + table + " WHERE name = '" + field1 + "' OR email = '" + field2 + "'"
}
`}, 1, gosec.NewConfig()},

	// Interprocedural with return value from tainted parameter
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
	"strings"
)

func handler(db *sql.DB, r *http.Request) {
	userInput := r.FormValue("search")
	sanitized := attemptSanitize(userInput)
	query := "SELECT * FROM users WHERE name = '" + sanitized + "'"
	db.Query(query)
}

func attemptSanitize(input string) string {
	// Ineffective sanitization - still tainted
	return strings.TrimSpace(input)
}
`}, 1, gosec.NewConfig()},

	// Complex Phi with loop and conditional
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	var result string
	items := r.URL.Query()["items"]
	for i, item := range items {
		if i == 0 {
			result = item
		} else {
			result = result + "," + item
		}
	}
	query := "SELECT * FROM users WHERE id IN (" + result + ")"
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Interprocedural with closure capturing tainted variable
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	userInput := r.FormValue("id")

	queryFunc := func(db *sql.DB) {
		query := "SELECT * FROM users WHERE id = '" + userInput + "'"
		db.Query(query)
	}

	queryFunc(db)
}
`}, 1, gosec.NewConfig()},

	// Multiple globals with taint propagation
	// NOTE: Global variable taint tracking not yet supported - documented limitation
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

var (
	globalFilter string
	globalTable  string
)

func handler(db *sql.DB, r *http.Request) {
	globalFilter = r.FormValue("filter")
	globalTable = "users"
	executeGlobalQuery(db)
}

func executeGlobalQuery(db *sql.DB) {
	query := "SELECT * FROM " + globalTable + " WHERE " + globalFilter
	db.Query(query)
}
`}, 0, gosec.NewConfig()},

	// Interprocedural with variadic function
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
	"strings"
)

func handler(db *sql.DB, r *http.Request) {
	id1 := r.FormValue("id1")
	id2 := r.FormValue("id2")
	query := buildQuery("users", id1, id2)
	db.Query(query)
}

func buildQuery(table string, ids ...string) string {
	return "SELECT * FROM " + table + " WHERE id IN ('" + strings.Join(ids, "','") + "')"
}
`}, 1, gosec.NewConfig()},

	// Complex Phi with ternary-like pattern
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	userInput := r.FormValue("query")
	var query string

	admin := r.Header.Get("X-Admin") == "true"
	if admin {
		query = "SELECT * FROM admin WHERE " + userInput
	} else {
		query = "SELECT * FROM users WHERE " + userInput
	}

	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Interprocedural with method receiver
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

type Database struct {
	db *sql.DB
}

func (d *Database) Search(filter string) {
	query := "SELECT * FROM users WHERE " + filter
	d.db.Query(query)
}

func handler(db *sql.DB, r *http.Request) {
	database := &Database{db: db}
	userFilter := r.FormValue("filter")
	database.Search(userFilter)
}
`}, 1, gosec.NewConfig()},

	// Global function pointer with tainted call
	// NOTE: Function pointer taint tracking not yet supported - documented limitation
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

var queryBuilder func(string) string

func init() {
	queryBuilder = func(input string) string {
		return "SELECT * FROM users WHERE name = '" + input + "'"
	}
}

func handler(db *sql.DB, r *http.Request) {
	userInput := r.FormValue("name")
	query := queryBuilder(userInput)
	db.Query(query)
}
`}, 0, gosec.NewConfig()},

	// Interprocedural with slice append operations
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
	"strings"
)

func handler(db *sql.DB, r *http.Request) {
	conditions := []string{}
	if name := r.FormValue("name"); name != "" {
		conditions = append(conditions, "name='"+name+"'")
	}
	if email := r.FormValue("email"); email != "" {
		conditions = append(conditions, "email='"+email+"'")
	}
	query := "SELECT * FROM users WHERE " + strings.Join(conditions, " AND ")
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Complex Phi with goto statement
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	var query string

	if r.Method == "GET" {
		query = r.URL.Query().Get("q")
		goto execute
	}

	query = r.FormValue("q")

execute:
	sql := "SELECT * FROM users WHERE search = '" + query + "'"
	db.Query(sql)
}
`}, 1, gosec.NewConfig()},

	// Interprocedural with interface implementation
	// NOTE: Interface method taint tracking not yet fully supported - documented limitation
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

type QueryExecutor interface {
	Execute(db *sql.DB, query string)
}

type SimpleExecutor struct{}

func (e *SimpleExecutor) Execute(db *sql.DB, query string) {
	db.Query(query)
}

func handler(db *sql.DB, r *http.Request) {
	userInput := r.FormValue("query")
	query := "SELECT * FROM users WHERE " + userInput

	var executor QueryExecutor = &SimpleExecutor{}
	executor.Execute(db, query)
}
`}, 0, gosec.NewConfig()},

	// Multiple Phi nodes with complex control flow
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	var table, filter string

	authLevel := r.Header.Get("Auth-Level")
	switch authLevel {
	case "admin":
		table = "admin_users"
		filter = r.FormValue("admin_filter")
	case "user":
		table = "users"
		filter = r.FormValue("user_filter")
	default:
		table = "public_users"
		filter = r.FormValue("public_filter")
	}

	var orderBy string
	if r.URL.Query().Get("sort") == "name" {
		orderBy = "name ASC"
	} else {
		orderBy = "created_at DESC"
	}

	query := "SELECT * FROM " + table + " WHERE " + filter + " ORDER BY " + orderBy
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Simple function return of tainted value
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func getUserInput(r *http.Request) string {
	return r.FormValue("input")
}

func handler(db *sql.DB, r *http.Request) {
	userInput := getUserInput(r)
	query := "SELECT * FROM users WHERE name = '" + userInput + "'"
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Taint through slice operations
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	filters := []string{r.FormValue("filter")}
	query := "SELECT * FROM users WHERE status = '" + filters[0] + "'"
	db.Query(query)
}
`}, 1, gosec.NewConfig()},

	// Multiple function call chain
	{[]string{`
package main

import (
	"database/sql"
	"net/http"
)

func getInput(r *http.Request) string {
	return r.FormValue("input")
}

func processInput(r *http.Request) string {
	return getInput(r)
}

func handler(db *sql.DB, r *http.Request) {
	userInput := processInput(r)
	query := "SELECT * FROM users WHERE name = '" + userInput + "'"
	db.Query(query)
}
`}, 1, gosec.NewConfig()},
}
