//go:build !windows

package workstation

import "fmt"

type collector struct{}

func New() Collector {
	return &collector{}
}

func (collector) Status() (Status, error) {
	return Status{}, fmt.Errorf("workstation collector is only available on Windows")
}
