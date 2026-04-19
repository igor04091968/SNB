package wts

import "snb-worktime-webui/internal/model"

type Collector interface {
	Snapshots() ([]model.Snapshot, error)
}
