package ctr

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestFormatArgsRedactsEnvValues(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "plain arguments",
			args: []string{"--address", "/run/containerd.sock", "tasks", "ls", "-q"},
			want: "--address /run/containerd.sock tasks ls -q",
		},
		{
			name: "separate env flag",
			args: []string{"run", "--env", "SECRET=value", "image"},
			want: "run --env SECRET=<redacted> image",
		},
		{
			name: "inline env flag",
			args: []string{"run", "--env=SECRET=value", "image"},
			want: "run --env=SECRET=<redacted> image",
		},
		{
			name: "multiple env values",
			args: []string{"run", "--env", "TOKEN=one", "--env=TWO=2", "--env", "THREE=three"},
			want: "run --env TOKEN=<redacted> --env=TWO=<redacted> --env THREE=<redacted>",
		},
		{
			name: "empty value",
			args: []string{"run", "--env", "EMPTY="},
			want: "run --env EMPTY=<redacted>",
		},
		{
			name: "non-env argument with equals",
			args: []string{"run", "--label", "BUILD=42", "--mount", "type=bind,src=/a,dst=/b"},
			want: "run --label BUILD=42 --mount type=bind,src=/a,dst=/b",
		},
		{
			name: "env file path",
			args: []string{"run", "--env-file", "/run/secrets.env", "image"},
			want: "run --env-file <redacted> image",
		},
		{
			name: "inline env file assignment",
			args: []string{"run", "--env-file=SECRET=value", "image"},
			want: "run --env-file=SECRET=<redacted> image",
		},
		{
			name: "env flag without value",
			args: []string{"run", "--env"},
			want: "run --env",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := formatArgs(test.args); got != test.want {
				t.Fatalf("formatArgs(%q) = %q, want %q", test.args, got, test.want)
			}
		})
	}
}

func TestCommandErrorsRedactEnvValues(t *testing.T) {
	for _, test := range []struct {
		name   string
		output []byte
		err    error
	}{
		{name: "process start failure", err: errors.New("fork/exec ctr: no such file or directory")},
		{name: "exit status", output: []byte("ctr: invalid environment"), err: errors.New("exit status 1")},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &fakeRunner{fn: func([]string) ([]byte, error) {
				return test.output, test.err
			}}
			client := newTestClient(t, runner)
			_, err := client.run(context.Background(), "run", "--env", "API_KEY=topsecret", "--env-file=/run/secret.env", "image")
			if err == nil {
				t.Fatal("failed command returned no error")
			}
			for _, secret := range []string{"topsecret", "/run/secret.env"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaked %q: %v", secret, err)
				}
			}
			for _, want := range []string{"--env API_KEY=<redacted>", "--env-file=<redacted>"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error %q does not contain %q", err, want)
				}
			}
			wantCall := strings.Join([]string{
				"ctr", "--address", "/tmp/containerd.sock", "--namespace", "rheic",
				"run", "--env", "API_KEY=topsecret", "--env-file=/run/secret.env", "image",
			}, " ")
			if got := strings.Join(runner.calls[0], " "); got != wantCall {
				t.Fatalf("executed command = %q, want %q", got, wantCall)
			}
		})
	}
}
