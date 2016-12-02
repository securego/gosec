package main

import "testing"

func Test_shouldInclude(t *testing.T) {
	type args struct {
		path     string
		excluded *fileList
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "non .go file",
			args: args{
				path:     "thing.txt",
				excluded: newFileList(),
			},
			want: false,
		},
		{
			name: ".go file, not excluded",
			args: args{
				path:     "thing.go",
				excluded: newFileList(),
			},
			want: true,
		},
		{
			name: ".go file, excluded",
			args: args{
				path:     "thing.go",
				excluded: newFileList("thing.go"),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		if got := shouldInclude(tt.args.path, tt.args.excluded); got != tt.want {
			t.Errorf("%q. shouldInclude() = %v, want %v", tt.name, got, tt.want)
		}
	}
}
