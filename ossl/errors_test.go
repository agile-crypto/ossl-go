//go:build cgo

package ossl

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// A reason code with no special meaning, chosen only to be recognisable in
// test failure output.
const testReason = 0x2a

func TestNewErrorDrainsQueue(t *testing.T) {
	clearErrors() // start from a known-empty queue regardless of test order
	raiseSyntheticError(testReason)

	err := newError("some op")
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("newError returned %T, want *Error", err)
	}
	if e.Op != "some op" {
		t.Fatalf("Op = %q, want %q", e.Op, "some op")
	}
	if len(e.Codes) == 0 || len(e.Msgs) == 0 {
		t.Fatalf("expected at least one queued entry, got Codes=%v Msgs=%v", e.Codes, e.Msgs)
	}
	if len(e.Codes) != len(e.Msgs) {
		t.Fatalf("Codes and Msgs length mismatch: %d vs %d", len(e.Codes), len(e.Msgs))
	}
	if !strings.Contains(err.Error(), "some op") {
		t.Fatalf("Error() = %q, want it to mention the op", err.Error())
	}

	// Draining is supposed to be exhaustive: a second call right after
	// should find nothing left over from the first.
	second := newError("second call")
	var e2 *Error
	errors.As(second, &e2)
	if len(e2.Codes) != 0 {
		t.Fatalf("queue not fully drained by the first newError call: %d entries remain", len(e2.Codes))
	}
}

func TestErrorWithNoQueuedEntries(t *testing.T) {
	clearErrors()
	err := newError("nothing failed")
	if got := err.Error(); !strings.Contains(got, "no detail on error queue") {
		t.Fatalf("Error() = %q, want the no-detail fallback message", got)
	}
}

func TestErrorReason(t *testing.T) {
	clearErrors()
	raiseSyntheticError(testReason)
	err := newError("op")
	var e *Error
	errors.As(err, &e)
	if len(e.Codes) == 0 {
		t.Fatal("no codes queued to test Reason against")
	}

	if !e.Reason(testReason) {
		t.Fatalf("Reason(%#x) = false, want true: this is the reason code that was raised", testReason)
	}
	if e.Reason(testReason + 1) {
		t.Fatalf("Reason(%#x) = true, want false: this reason code was never raised", testReason+1)
	}
}

func TestErrVerificationIs(t *testing.T) {
	wrapped := fmt.Errorf("decrypt: %w", ErrVerification)
	if !errors.Is(wrapped, ErrVerification) {
		t.Fatal("errors.Is failed to match a wrapped ErrVerification")
	}
	if errors.Is(wrapped, ErrClosed) {
		t.Fatal("a wrapped ErrVerification incorrectly matched ErrClosed")
	}
}

func TestErrClosedIs(t *testing.T) {
	wrapped := fmt.Errorf("key: %w", ErrClosed)
	if !errors.Is(wrapped, ErrClosed) {
		t.Fatal("errors.Is failed to match a wrapped ErrClosed")
	}
	if errors.Is(wrapped, ErrVerification) {
		t.Fatal("a wrapped ErrClosed incorrectly matched ErrVerification")
	}
}

// TestClearErrorsPreventsMisattribution reproduces the pitfall directly
// rather than just describing it: an error left on the queue by an earlier,
// undrained failure is still there when something unrelated checks the
// queue afterward, and would be wrongly blamed on whatever runs next unless
// something calls clearErrors() first.
func TestClearErrorsPreventsMisattribution(t *testing.T) {
	clearErrors()
	raiseSyntheticError(testReason) // deliberately not drained yet - this is the bug being reproduced

	if peekError() == 0 {
		t.Fatal("test setup failed: expected a queued error before clearErrors")
	}

	clearErrors()

	if peekError() != 0 {
		t.Fatal("clearErrors did not empty the queue")
	}
}
