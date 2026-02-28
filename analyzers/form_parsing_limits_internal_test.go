package analyzers

import (
	"go/constant"
	"go/types"
	"testing"

	"golang.org/x/tools/go/ssa"
)

func TestDependencyCheckerHandlesPhiCycleWithoutTarget(t *testing.T) {
	t.Parallel()

	checker := newDependencyChecker()
	target := ssa.NewConst(constant.MakeInt64(42), types.Typ[types.Int])

	phiA := &ssa.Phi{}
	phiB := &ssa.Phi{}
	phiA.Edges = []ssa.Value{phiB}
	phiB.Edges = []ssa.Value{phiA}

	if checker.dependsOn(phiA, target) {
		t.Fatal("expected false for cycle without target dependency")
	}
}

func TestDependencyCheckerFindsTargetInPhiCycle(t *testing.T) {
	t.Parallel()

	checker := newDependencyChecker()
	target := ssa.NewConst(constant.MakeInt64(7), types.Typ[types.Int])

	phiA := &ssa.Phi{}
	phiB := &ssa.Phi{}
	phiA.Edges = []ssa.Value{phiB, target}
	phiB.Edges = []ssa.Value{phiA}

	if !checker.dependsOn(phiA, target) {
		t.Fatal("expected true when cycle has a path to target")
	}

	if !checker.dependsOn(phiA, target) {
		t.Fatal("expected stable memoized result on repeated call")
	}
}

func TestValueDependsOnHandlesPhiCycleWithoutTarget(t *testing.T) {
	t.Parallel()

	target := ssa.NewConst(constant.MakeInt64(42), types.Typ[types.Int])

	phiA := &ssa.Phi{}
	phiB := &ssa.Phi{}
	phiA.Edges = []ssa.Value{phiB}
	phiB.Edges = []ssa.Value{phiA}

	if valueDependsOn(phiA, target, 0) {
		t.Fatal("expected false for Phi cycle with no path to target")
	}
}

func TestValueDependsOnFindsTargetInPhiCycle(t *testing.T) {
	t.Parallel()

	target := ssa.NewConst(constant.MakeInt64(7), types.Typ[types.Int])

	phiA := &ssa.Phi{}
	phiB := &ssa.Phi{}
	phiA.Edges = []ssa.Value{phiB, target}
	phiB.Edges = []ssa.Value{phiA}

	if !valueDependsOn(phiA, target, 0) {
		t.Fatal("expected true when cycle has a path to target")
	}

	if !valueDependsOn(phiA, target, 0) {
		t.Fatal("expected stable result on repeated call")
	}
}

func TestValueDependsOnSelfReferentialPhi(t *testing.T) {
	t.Parallel()

	target := ssa.NewConst(constant.MakeInt64(1), types.Typ[types.Int])

	phi := &ssa.Phi{}
	phi.Edges = []ssa.Value{phi}

	if valueDependsOn(phi, target, 0) {
		t.Fatal("expected false for self-referential Phi with no path to target")
	}
}
