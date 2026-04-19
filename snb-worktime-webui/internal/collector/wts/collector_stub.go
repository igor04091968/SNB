//go:build !windows

package wts

import (
	"fmt"

	"snb-worktime-webui/internal/model"
)

type collector struct{}

func New() Collector {
	return &collector{}
}

func (collector) Snapshots() ([]model.Snapshot, error) {
	return nil, fmt.Errorf("WTS collector is only available on Windows")
}
