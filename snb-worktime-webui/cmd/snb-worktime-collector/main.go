package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"snb-worktime-webui/internal/collector/wts"
)

func main() {
	outputPath := flag.String("output", "-", "output path or - for stdout")
	appendMode := flag.Bool("append", false, "append to output file instead of truncating it")
	flag.Parse()

	collector := wts.New()
	snapshots, err := collector.Snapshots()
	if err != nil {
		fmt.Fprintf(os.Stderr, "collect snapshots: %v\n", err)
		os.Exit(1)
	}

	writer, closeWriter, err := openWriter(*outputPath, *appendMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open output: %v\n", err)
		os.Exit(1)
	}
	defer closeWriter()

	encoder := json.NewEncoder(writer)
	for _, snapshot := range snapshots {
		if err := encoder.Encode(snapshot); err != nil {
			fmt.Fprintf(os.Stderr, "encode snapshot: %v\n", err)
			os.Exit(1)
		}
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
