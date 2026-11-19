package ctr

import (
	"context"
	"strings"
	"testing"

	runtime "github.com/rheic/sandboxes-runtime"
)

func TestSkillsMountFailsClosedBeforeRuntimeActivity(t *testing.T) {
	backend := &Backend{}
	for _, readOnly := range []bool{true, false} {
		_, err := backend.Create(context.Background(), runtime.Config{Skills: &runtime.SkillsMount{
			StorePath: "/synthetic/skills", HelperPath: "/synthetic/helper", AgentPath: "/home/agent/.agents/skills", ReadOnly: readOnly,
		}})
		if err == nil || !strings.Contains(err.Error(), "race-safe source binding") {
			t.Fatalf("readOnly=%t: got error %v", readOnly, err)
		}
	}
}
