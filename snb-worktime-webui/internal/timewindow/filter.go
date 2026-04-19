package timewindow

import "time"

func Duration(start time.Time, end time.Time, since time.Time, until time.Time, dayStartMinutes int, dayEndMinutes int) time.Duration {
	start, end, ok := clipRange(start, end, since, until)
	if !ok {
		return 0
	}
	if !hasDayWindow(dayStartMinutes, dayEndMinutes) {
		return end.Sub(start)
	}

	var total time.Duration
	dayCursor := midnightUTC(start)
	lastDay := midnightUTC(end)

	for !dayCursor.After(lastDay) {
		windowStart := dayCursor.Add(time.Duration(dayStartMinutes) * time.Minute)
		windowEnd := dayCursor.Add(time.Duration(dayEndMinutes) * time.Minute)
		clippedStart, clippedEnd, ok := clipRange(start, end, windowStart, windowEnd)
		if ok {
			total += clippedEnd.Sub(clippedStart)
		}
		dayCursor = dayCursor.Add(24 * time.Hour)
	}

	return total
}

func Clip(start time.Time, end time.Time, since time.Time, until time.Time) (time.Time, time.Time, bool) {
	return clipRange(start, end, since, until)
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

func midnightUTC(moment time.Time) time.Time {
	return time.Date(moment.UTC().Year(), moment.UTC().Month(), moment.UTC().Day(), 0, 0, 0, 0, time.UTC)
}
