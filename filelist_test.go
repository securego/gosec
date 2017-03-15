package main

import (
	"reflect"
	"testing"
)

func Test_newFileList(t *testing.T) {
	type args struct {
		paths []string
	}
	tests := []struct {
		name string
		args args
		want *fileList
	}{
		{
			name: "nil paths",
			args: args{paths: nil},
			want: &fileList{patterns: map[string]struct{}{}},
		},
		{
			name: "empty paths",
			args: args{paths: []string{}},
			want: &fileList{patterns: map[string]struct{}{}},
		},
		{
			name: "have paths",
			args: args{paths: []string{"*_test.go"}},
			want: &fileList{patterns: map[string]struct{}{
				"*_test.go": struct{}{},
			}},
		},
	}
	for _, tt := range tests {
		if got := newFileList(tt.args.paths...); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%q. newFileList() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func Test_fileList_String(t *testing.T) {
	type fields struct {
		patterns []string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name:   "nil patterns",
			fields: fields{patterns: nil},
			want:   "",
		},
		{
			name:   "empty patterns",
			fields: fields{patterns: []string{}},
			want:   "",
		},
		{
			name:   "one pattern",
			fields: fields{patterns: []string{"foo"}},
			want:   "foo",
		},
		{
			name:   "two patterns",
			fields: fields{patterns: []string{"bar", "foo"}},
			want:   "bar, foo",
		},
	}
	for _, tt := range tests {
		f := newFileList(tt.fields.patterns...)
		if got := f.String(); got != tt.want {
			t.Errorf("%q. fileList.String() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func Test_fileList_Set(t *testing.T) {
	type fields struct {
		patterns []string
	}
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    map[string]struct{}
		wantErr bool
	}{
		{
			name:    "add empty path",
			fields:  fields{patterns: nil},
			args:    args{path: ""},
			want:    map[string]struct{}{},
			wantErr: false,
		},
		{
			name:   "add path to nil patterns",
			fields: fields{patterns: nil},
			args:   args{path: "foo"},
			want: map[string]struct{}{
				"foo": struct{}{},
			},
			wantErr: false,
		},
		{
			name:   "add path to empty patterns",
			fields: fields{patterns: []string{}},
			args:   args{path: "foo"},
			want: map[string]struct{}{
				"foo": struct{}{},
			},
			wantErr: false,
		},
		{
			name:   "add path to populated patterns",
			fields: fields{patterns: []string{"foo"}},
			args:   args{path: "bar"},
			want: map[string]struct{}{
				"foo": struct{}{},
				"bar": struct{}{},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		f := newFileList(tt.fields.patterns...)
		if err := f.Set(tt.args.path); (err != nil) != tt.wantErr {
			t.Errorf("%q. fileList.Set() error = %v, wantErr %v", tt.name, err, tt.wantErr)
		}
		if !reflect.DeepEqual(f.patterns, tt.want) {
			t.Errorf("%q. got state fileList.patterns = %v, want state %v", tt.name, f.patterns, tt.want)
		}
	}
}

func Test_fileList_Contains(t *testing.T) {
	type fields struct {
		patterns []string
	}
	type args struct {
		path string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name:   "nil patterns",
			fields: fields{patterns: nil},
			args:   args{path: "foo"},
			want:   false,
		},
		{
			name:   "empty patterns",
			fields: fields{patterns: nil},
			args:   args{path: "foo"},
			want:   false,
		},
		{
			name:   "one pattern, no wildcard, no match",
			fields: fields{patterns: []string{"foo"}},
			args:   args{path: "bar"},
			want:   false,
		},
		{
			name:   "one pattern, no wildcard, match",
			fields: fields{patterns: []string{"foo"}},
			args:   args{path: "foo"},
			want:   true,
		},
		{
			name:   "one pattern, wildcard prefix, match",
			fields: fields{patterns: []string{"*foo"}},
			args:   args{path: "foo"},
			want:   true,
		},
		{
			name:   "one pattern, wildcard suffix, match",
			fields: fields{patterns: []string{"foo*"}},
			args:   args{path: "foo"},
			want:   true,
		},
		{
			name:   "one pattern, wildcard both ends, match",
			fields: fields{patterns: []string{"*foo*"}},
			args:   args{path: "foo"},
			want:   true,
		},
		{
			name:   "default test match 1",
			fields: fields{patterns: []string{"*_test.go"}},
			args:   args{path: "foo_test.go"},
			want:   true,
		},
		{
			name:   "default test match 2",
			fields: fields{patterns: []string{"*_test.go"}},
			args:   args{path: "bar/foo_test.go"},
			want:   true,
		},
		{
			name:   "default test match 3",
			fields: fields{patterns: []string{"*_test.go"}},
			args:   args{path: "/bar/foo_test.go"},
			want:   true,
		},
		{
			name:   "default test match 4",
			fields: fields{patterns: []string{"*_test.go"}},
			args:   args{path: "baz/bar/foo_test.go"},
			want:   true,
		},
		{
			name:   "default test match 5",
			fields: fields{patterns: []string{"*_test.go"}},
			args:   args{path: "/baz/bar/foo_test.go"},
			want:   true,
		},
		{
			name:   "many patterns, no match",
			fields: fields{patterns: []string{"*_one.go", "*_two.go"}},
			args:   args{path: "/baz/bar/foo_test.go"},
			want:   false,
		},
		{
			name:   "many patterns, match",
			fields: fields{patterns: []string{"*_one.go", "*_two.go", "*_test.go"}},
			args:   args{path: "/baz/bar/foo_test.go"},
			want:   true,
		},
	}
	for _, tt := range tests {
		f := newFileList(tt.fields.patterns...)
		if got := f.Contains(tt.args.path); got != tt.want {
			t.Errorf("%q. fileList.Contains() = %v, want %v", tt.name, got, tt.want)
		}
	}
}
