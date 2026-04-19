package timewindow

import "time"

type Segment struct {
	Start time.Time
	End   time.Time
}

func Duration(start time.Time, end time.Time, since time.Time, until time.Time, dayStartMinutes int, dayEndMinutes int, location *time.Location) time.Duration {
	var total time.Duration
	for _, segment := range Segments(start, end, since, until, dayStartMinutes, dayEndMinutes, location) {
		total += segment.End.Sub(segment.Start)
	}
	return total
}

func Clip(start time.Time, end time.Time, since time.Time, until time.Time) (time.Time, time.Time, bool) {
	return clipRange(start, end, since, until)
}

func Segments(start time.Time, end time.Time, since time.Time, until time.Time, dayStartMinutes int, dayEndMinutes int, location *time.Location) []Segment {
	start, end, ok := clipRange(start, end, since, until)
	if !ok {
		return nil
	}
	if !hasDayWindow(dayStartMinutes, dayEndMinutes) {
		return []Segment{{Start: start, End: end}}
	}

	if location == nil {
		location = time.UTC
	}
	dayCursor := midnightInLocation(start, location)
	lastDay := midnightInLocation(end, location)
	var segments []Segment

	for !dayCursor.After(lastDay) {
		windowStart := dayCursor.Add(time.Duration(dayStartMinutes) * time.Minute)
		windowEnd := dayCursor.Add(time.Duration(dayEndMinutes) * time.Minute)
		clippedStart, clippedEnd, ok := clipRange(start, end, windowStart.UTC(), windowEnd.UTC())
		if ok {
			segments = append(segments, Segment{Start: clippedStart, End: clippedEnd})
		}
		dayCursor = dayCursor.Add(24 * time.Hour)
	}

	return segments
}

func hasDayWindow(dayStartMinutes int, dayEndMinutes int) bool {
	return dayStartMinutes >= 0 && dayEndMinutes > dayStartMinutes && dayEndMinutes <= 24*60
}

func clipRange(start time.Time, end time.Time, since time.Time, until time.Time) (time.Time, time.Time, bool) {
	if end.Before(start) || end.Equal(start) {
		return time.Time{}, time.Time{}, false
	}
	if !since.IsZero() && start.Before(since) {
		start = since
	}
	if !until.IsZero() && end.After(until) {
		end = until
	}
	if !end.After(start) {
		return time.Time{}, time.Time{}, false
	}
	return start, end, true
}

func midnightInLocation(moment time.Time, location *time.Location) time.Time {
	local := moment.In(location)
	return time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, location)
}
