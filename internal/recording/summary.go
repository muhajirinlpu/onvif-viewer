package recording

import (
	"errors"
	"time"
)

// SummaryBucket is one interval of the timeline strip. A bucket deliberately
// reports both recorded and gap seconds so the UI can draw an honest
// proportion rather than inferring continuity from the absence of a gap row.
type SummaryBucket struct {
	Start           time.Time `json:"start"`
	End             time.Time `json:"end"`
	RecordedSeconds float64   `json:"recordedSeconds"`
	GapSeconds      float64   `json:"gapSeconds"`
	Segments        int       `json:"segments"`
}

// SummaryCoverage echoes the requested window back so the client draws the strip
// against the window it actually asked for.
type SummaryCoverage struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// Summary is the bounded histogram behind the timeline. Truncated is set when
// the catalog read hit MaxSummarySegments, so the UI can say the strip is
// incomplete instead of drawing a misleadingly short one.
type Summary struct {
	Buckets   []SummaryBucket `json:"buckets"`
	Coverage  SummaryCoverage `json:"coverage"`
	Truncated bool            `json:"truncated"`
}

// Summary buckets coverage for one camera into at most MaxSummaryBuckets
// intervals. Gap seconds come only from state='gap' rows: an absent gap does
// NOT prove continuous footage, so the UI must say "no gap recorded".
func (r *Recorder) Summary(camera string, from, to time.Time, buckets int) (Summary, error) {
	if !validIdentity(camera) || !to.After(from) || to.Sub(from) > 31*24*time.Hour {
		return Summary{}, errors.New("invalid bounded interval")
	}
	from, to = from.UTC(), to.UTC()
	if buckets <= 0 {
		buckets = MaxSummaryBuckets
	}
	if buckets > MaxSummaryBuckets {
		buckets = MaxSummaryBuckets
	}
	width := to.Sub(from) / time.Duration(buckets)
	if width <= 0 {
		width = time.Second
	}
	// Bucket windows tile [from,to) exactly; the last bucket absorbs the
	// remainder so the strip always ends at the requested end time.
	bounds := make([]time.Time, buckets+1)
	for i := 0; i <= buckets; i++ {
		bounds[i] = from.Add(time.Duration(i) * width)
	}
	bounds[buckets] = to

	rows, err := r.db.Query(`SELECT start_ns,end_ns,duration,state FROM recording_segments WHERE camera=? AND end_ns>? AND start_ns<? AND state IN ('staged','ready','gap') ORDER BY start_ns,id LIMIT ?`,
		camera, from.UnixNano(), to.UnixNano(), MaxSummarySegments+1)
	if err != nil {
		return Summary{}, err
	}
	defer rows.Close()
	type span struct {
		start, end int64
		duration   float64
		gap        bool
	}
	var spans []span
	for rows.Next() {
		var s span
		var state string
		if err := rows.Scan(&s.start, &s.end, &s.duration, &state); err != nil {
			return Summary{}, err
		}
		s.gap = state == "gap"
		spans = append(spans, s)
	}
	if err := rows.Err(); err != nil {
		return Summary{}, err
	}
	truncated := len(spans) > MaxSummarySegments
	if truncated {
		spans = spans[:MaxSummarySegments]
	}

	out := Summary{Coverage: SummaryCoverage{From: from, To: to}, Truncated: truncated}
	if len(spans) == 0 {
		return out, nil
	}
	bucketed := make([]SummaryBucket, buckets)
	for i := 0; i < buckets; i++ {
		bucketed[i] = SummaryBucket{Start: bounds[i], End: bounds[i+1]}
	}
	spanStart, spanEnd := from.UnixNano(), to.UnixNano()
	for _, s := range spans {
		start, end := s.start, s.end
		if start < spanStart {
			start = spanStart
		}
		if end > spanEnd {
			end = spanEnd
		}
		// Seconds are the part of the row that falls inside the requested
		// window. A bounded discontinuity marker is written with zero width, so
		// its declared duration is the only evidence of how long the gap was;
		// without this it would contribute nothing and the strip would draw a
		// gap as if it had never happened.
		seconds := float64(end-start) / float64(time.Second)
		if seconds < 0 {
			seconds = 0
		}
		if s.duration > 0 {
			if seconds == 0 || seconds > s.duration {
				seconds = s.duration
			}
		}
		if seconds <= 0 {
			continue
		}
		first := indexOf(bounds, start)
		last := indexOf(bounds, end-1)
		if last < first {
			last = first
		}
		per := seconds / float64(last-first+1)
		for i := first; i <= last && i < buckets; i++ {
			if i < 0 {
				continue
			}
			bucketed[i].Segments++
			if s.gap {
				bucketed[i].GapSeconds += per
			} else {
				bucketed[i].RecordedSeconds += per
			}
		}
	}
	out.Buckets = bucketed
	return out, nil
}

// indexOf finds the bucket containing ns, clamping to [0, len(bounds)-2].
func indexOf(bounds []time.Time, ns int64) int {
	lo, hi := 0, len(bounds)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if bounds[mid].UnixNano() <= ns {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	if lo >= len(bounds)-1 {
		return len(bounds) - 2
	}
	return lo
}
