package checks

import (
	"testing"
	"time"
)

// sample builds a TimingSample from millisecond values.
func sample(ms ...int) TimingSample {
	durations := make([]time.Duration, 0, len(ms))
	for _, value := range ms {
		durations = append(durations, time.Duration(value)*time.Millisecond)
	}
	return summariseTiming(durations)
}

func TestSummariseTiming(t *testing.T) {
	timing := sample(100, 110, 120, 130, 140)

	if timing.Median != 120*time.Millisecond {
		t.Errorf("median = %v, want 120ms", timing.Median)
	}
	if timing.Min != 100*time.Millisecond || timing.Max != 140*time.Millisecond {
		t.Errorf("bounds = %v..%v", timing.Min, timing.Max)
	}
	// Q1 = 110ms, Q3 = 130ms.
	if timing.IQR != 20*time.Millisecond {
		t.Errorf("IQR = %v, want 20ms", timing.IQR)
	}
}

func TestSummariseTimingIsOutlierResistant(t *testing.T) {
	// One stalled request must not move the verdict: this is why the median is
	// used rather than the mean.
	clean := sample(100, 100, 100, 100, 100)
	withSpike := sample(100, 100, 100, 100, 3000)

	if clean.Median != withSpike.Median {
		t.Errorf("a single spike moved the median: %v vs %v", clean.Median, withSpike.Median)
	}
}

func TestSummariseTimingHandlesEdges(t *testing.T) {
	if got := summariseTiming(nil); len(got.Samples) != 0 || got.Median != 0 {
		t.Errorf("nil samples produced %+v", got)
	}
	single := sample(42)
	if single.Median != 42*time.Millisecond || single.IQR != 0 {
		t.Errorf("single sample = %+v", single)
	}
}

// TestJudgeTimingAcceptsARealDelay is the case the check exists for: a pause
// that reaches the requested magnitude, stands clear of the noise, and is
// consistent.
func TestJudgeTimingAcceptsARealDelay(t *testing.T) {
	baseline := sample(120, 125, 130, 135, 140)
	injected := sample(5120, 5140, 5150, 5160, 5180)

	verdict := JudgeTiming(baseline, injected, 5*time.Second)
	if !verdict.Delayed {
		t.Fatalf("a real 5s delay was not accepted: %s", verdict.Reason)
	}
	if verdict.Delta < 4*time.Second {
		t.Errorf("delta = %v, want about 5s", verdict.Delta)
	}
	if verdict.Reason == "" {
		t.Error("no reason was recorded")
	}
}

// TestJudgeTimingRejectsNoise: a target whose responses wander must not be
// reported on the strength of one slow answer.
func TestJudgeTimingRejectsNoise(t *testing.T) {
	// A slow target with a wide spread, and an "injected" set that is simply
	// further up the same distribution.
	baseline := sample(200, 400, 600, 800, 1000)
	injected := sample(600, 800, 1000, 1200, 1400)

	verdict := JudgeTiming(baseline, injected, 5*time.Second)
	if verdict.Delayed {
		t.Errorf("network jitter was reported as injection: %s", verdict.Reason)
	}
}

// TestJudgeTimingRejectsTooSmallADelay: the payload asked to sleep five seconds
// and the target got a little slower. That is not the payload working.
func TestJudgeTimingRejectsTooSmallADelay(t *testing.T) {
	baseline := sample(100, 101, 102, 103, 104)
	injected := sample(500, 501, 502, 503, 504)

	verdict := JudgeTiming(baseline, injected, 5*time.Second)
	if verdict.Delayed {
		t.Errorf("a delay far short of the requested one was accepted: %s", verdict.Reason)
	}
}

// TestJudgeTimingRejectsAnInconsistentDelay is the reproducibility rule: a
// payload that sleeps sometimes cannot be attributed a delay.
func TestJudgeTimingRejectsAnInconsistentDelay(t *testing.T) {
	baseline := sample(100, 101, 102, 103, 104)
	// Median is high, but the spread is enormous.
	injected := sample(200, 800, 5000, 9000, 12000)

	verdict := JudgeTiming(baseline, injected, 5*time.Second)
	if verdict.Delayed {
		t.Errorf("an unreproducible delay was accepted: %s", verdict.Reason)
	}
}

func TestJudgeTimingRejectsEmptySamples(t *testing.T) {
	if verdict := JudgeTiming(TimingSample{}, sample(5000, 5000, 5000), time.Second); verdict.Delayed {
		t.Error("a verdict was reached with no baseline")
	}
	if verdict := JudgeTiming(sample(100, 100, 100), TimingSample{}, time.Second); verdict.Delayed {
		t.Error("a verdict was reached with no injected samples")
	}
}

func TestQuantile(t *testing.T) {
	values := []time.Duration{
		10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond,
		40 * time.Millisecond, 50 * time.Millisecond,
	}
	cases := map[float64]time.Duration{
		0:    10 * time.Millisecond,
		0.25: 20 * time.Millisecond,
		0.5:  30 * time.Millisecond,
		0.75: 40 * time.Millisecond,
		1:    50 * time.Millisecond,
	}
	for fraction, want := range cases {
		if got := quantile(values, fraction); got != want {
			t.Errorf("quantile(%v) = %v, want %v", fraction, got, want)
		}
	}
	if got := quantile(nil, 0.5); got != 0 {
		t.Errorf("quantile(nil) = %v", got)
	}
}

func TestMaxDuration(t *testing.T) {
	if got := maxDuration(time.Second, 5*time.Second, 2*time.Second); got != 5*time.Second {
		t.Errorf("maxDuration = %v", got)
	}
	if got := maxDuration(); got != 0 {
		t.Errorf("maxDuration() = %v", got)
	}
}
