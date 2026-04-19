package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"snb-worktime-webui/internal/collector/workstation"
)

func main() {
	outputPath := flag.String("output", "-", "output path or - for stdout")
	appendMode := flag.Bool("append", false, "append to output file instead of truncating it")
	windowSeconds := flag.Int("window-seconds", 60, "activity window duration in seconds")
	idleThresholdSeconds := flag.Int("idle-threshold-seconds", 60, "max idle seconds still treated as active")
	flag.Parse()

	collector := workstation.New()
	status, err := collector.Status()
	if err != nil {
		fmt.Fprintf(os.Stderr, "collect workstation status: %v\n", err)
		os.Exit(1)
	}

	window, ok := workstation.BuildActivityWindow(
		status,
		time.Duration(*windowSeconds)*time.Second,
		time.Duration(*idleThresholdSeconds)*time.Second,
	)
	if !ok {
		return
	}

	writer, closeWriter, err := openWriter(*outputPath, *appendMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open output: %v\n", err)
		os.Exit(1)
	}
	defer closeWriter()

	if err := json.NewEncoder(writer).Encode(window); err != nil {
		fmt.Fprintf(os.Stderr, "encode activity window: %v\n", err)
		os.Exit(1)
	}
}

func openWriter(outputPath string, appendMode bool) (*os.File, func(), error) {
	if outputPath == "-" {
		return os.Stdout, func() {}, nil
	}

	flags := os.O_CREATE | os.O_WRONLY
	if appendMode {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}

	file, err := os.OpenFile(outputPath, flags, 0o644)
	if err != nil {
		return nil, nil, err
	}
	return file, func() { _ = file.Close() }, nil
}
