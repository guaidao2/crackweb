package checks

import (
	"context"
	"sort"
	"time"
)

// TimingSample summarises repeated measurements of how long a request takes.
//
// The median and the interquartile range are used rather than the mean and the
// standard deviation on purpose. A single network hiccup moves a mean by
// hundreds of milliseconds and a standard deviation by more; the middle half of
// the samples is not disturbed by one outlier, which is exactly the property a
// timing verdict needs.
type TimingSample struct {
	// Samples holds every measurement, sorted.
	Samples []time.Duration
	// Median is the middle value.
	Median time.Duration
	// IQR is the interquartile range: how much the middle half varies. It is the
	// measurement's own estimate of its noise.
	IQR time.Duration
	// Min and Max bound the samples.
	Min, Max time.Duration
}

// TimingVerdict is the outcome of a time-based test.
type TimingVerdict struct {
	// Delayed reports that the payload demonstrably slowed the target down.
	Delayed bool
	// Baseline and Injected are the two samples the verdict rests on.
	Baseline, Injected TimingSample
	// Delta is the difference between the medians.
	Delta time.Duration
	// Reason explains the verdict in one line, for the evidence block.
	Reason string
}

// DefaultTimingSamples is how many measurements a time-based check takes once it
// has reason to look closer.
const DefaultTimingSamples = 5

// timingNoiseFloor is the smallest variation treated as real. Below it, any
// difference is measurement error rather than a signal.
const timingNoiseFloor = 150 * time.Millisecond

// MeasureTiming sends the same payload repeatedly and summarises the durations.
//
// The encoding is a parameter rather than a decision made here, so that the
// bytes measured are the bytes that were judged to be worth measuring.
func (c *Context) MeasureTiming(ctx context.Context, t *Target, payload string, encoding Encoding, samples int) (TimingSample, error) {
	return c.MeasureTimingTimed(ctx, t, payload, encoding, samples, 0)
}

// MeasureTimingTimed is MeasureTiming with a deadline for each sample.
func (c *Context) MeasureTimingTimed(ctx context.Context, t *Target, payload string, encoding Encoding, samples int, timeout time.Duration) (TimingSample, error) {
	if samples < 1 {
		samples = 1
	}
	durations := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		if err := ctx.Err(); err != nil {
			break
		}
		_, response, err := c.InjectEncodedTimed(ctx, t, payload, encoding, timeout)
		if err != nil || response == nil {
			continue
		}
		durations = append(durations, response.Duration)
	}
	return summariseTiming(durations), nil
}

// summariseTiming computes the robust statistics for a set of measurements.
func summariseTiming(durations []time.Duration) TimingSample {
	if len(durations) == 0 {
		return TimingSample{}
	}
	sorted := append([]time.Duration(nil), durations...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	return TimingSample{
		Samples: sorted,
		Median:  quantile(sorted, 0.50),
		IQR:     quantile(sorted, 0.75) - quantile(sorted, 0.25),
		Min:     sorted[0],
		Max:     sorted[len(sorted)-1],
	}
}

// quantile returns the value at a fraction of the sorted sample, using linear
// interpolation between neighbours.
func quantile(sorted []time.Duration, fraction float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	position := fraction * float64(len(sorted)-1)
	lower := int(position)
	upper := lower + 1
	if upper >= len(sorted) {
		return sorted[len(sorted)-1]
	}
	weight := position - float64(lower)
	return time.Duration(float64(sorted[lower])*(1-weight) + float64(sorted[upper])*weight)
}

// JudgeTiming decides whether an injected delay is real.
//
// Three conditions have to hold together, and each one rules out a different way
// of being wrong:
//
//  1. The delay reaches most of what the payload asked for. A payload that
//     sleeps five seconds and adds one is not sleeping.
//  2. The delay is several times the measured noise. A slow target with a wide
//     spread produces differences of hundreds of milliseconds on its own.
//  3. The injected samples are tight. If the same payload gives three seconds
//     once and half a second the next time, the delay is not attributable to the
//     payload — and a finding that cannot be reproduced is worse than no finding.
//
// Requiring all three is what makes the result worth reporting: a scanner that
// calls every slow response a time-based injection trains its readers to ignore
// it.
func JudgeTiming(baseline, injected TimingSample, expected time.Duration) TimingVerdict {
	verdict := TimingVerdict{Baseline: baseline, Injected: injected}

	if len(baseline.Samples) == 0 || len(injected.Samples) == 0 {
		verdict.Reason = "not enough measurements"
		return verdict
	}

	verdict.Delta = injected.Median - baseline.Median

	// 1. Magnitude: the delay has to be most of what was asked for.
	if expected > 0 && verdict.Delta < expected*7/10 {
		verdict.Reason = "the added delay was smaller than the payload requested"
		return verdict
	}

	// 2. Signal above noise.
	noise := maxDuration(baseline.IQR, injected.IQR, timingNoiseFloor)
	if verdict.Delta < noise*3 {
		verdict.Reason = "the difference is within the target's own variation"
		return verdict
	}

	// 3. Stability of the injected measurements.
	if expected > 0 && injected.IQR > expected/2 {
		verdict.Reason = "the delayed responses were not consistent enough to attribute the delay"
		return verdict
	}

	verdict.Delayed = true
	verdict.Reason = "the delay reproduced across measurements and exceeded the target's own variation"
	return verdict
}

// maxDuration returns the largest of its arguments.
func maxDuration(values ...time.Duration) time.Duration {
	best := time.Duration(0)
	for _, value := range values {
		if value > best {
			best = value
		}
	}
	return best
}

// TimingScreen is the cheap first pass: one baseline request and one injected
// request. Only if the single injected response is meaningfully slower does a
// check spend the requests a full measurement costs.
//
// It is deliberately permissive — it lets through anything that might be real —
// because its job is to avoid work, not to decide. The verdict comes from
// JudgeTiming, which is strict.
func (c *Context) TimingScreen(ctx context.Context, t *Target, payload string, encoding Encoding, expected time.Duration) (bool, error) {
	_, baseline, err := c.InjectEncoded(ctx, t, t.Param.Value, encoding)
	if err != nil || baseline == nil {
		return false, err
	}
	_, injected, err := c.InjectEncoded(ctx, t, payload, encoding)
	if err != nil || injected == nil {
		return false, err
	}
	// A quarter of the requested delay is enough to be worth measuring properly;
	// noise is filtered by the real verdict, not here.
	return injected.Duration-baseline.Duration >= expected/4, nil
}
