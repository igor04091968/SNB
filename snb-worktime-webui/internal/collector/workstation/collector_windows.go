//go:build windows

package workstation

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wtsCurrentServerHandle = 0
	wtsInfoCurrentSession  = 0xffffffff
	wtsInfoSessionInfoEx   = 25
	wtsSessionStateLock    = 0
	wtsSessionStateUnlock  = 1
)

var (
	modUser32                      = windows.NewLazySystemDLL("user32.dll")
	modWtsapi32                    = windows.NewLazySystemDLL("wtsapi32.dll")
	procGetLastInputInfo           = modUser32.NewProc("GetLastInputInfo")
	procWTSQuerySessionInformation = modWtsapi32.NewProc("WTSQuerySessionInformationW")
)

type collector struct {
	serverName string
}

type lastInputInfo struct {
	CbSize uint32
	DwTime uint32
}

type wtsInfoEx struct {
	Level uint32
	Data  wtsInfoExLevel
}

type wtsInfoExLevel struct {
	Level1 wtsInfoExLevel1
}

type wtsInfoExLevel1 struct {
	SessionID               uint32
	SessionState            uint32
	SessionFlags            int32
	WinStationName          [33]uint16
	UserName                [21]uint16
	DomainName              [18]uint16
	LogonTime               int64
	ConnectTime             int64
	DisconnectTime          int64
	LastInputTime           int64
	CurrentTime             int64
	IncomingBytes           uint32
	OutgoingBytes           uint32
	IncomingFrames          uint32
	OutgoingFrames          uint32
	IncomingCompressedBytes uint32
	OutgoingCompressedBytes uint32
}

func New() Collector {
	serverName, err := os.Hostname()
	if err != nil {
		serverName = ""
	}
	return &collector{serverName: serverName}
}

func (c *collector) Status() (Status, error) {
	username, err := currentUser()
	if err != nil {
		return Status{}, err
	}

	infoEx, err := queryCurrentSessionInfoEx()
	if err != nil {
		return Status{}, fmt.Errorf("query current session info: %w", err)
	}

	idleSeconds, err := currentIdleSeconds()
	if err != nil {
		return Status{}, fmt.Errorf("get idle time: %w", err)
	}

	clientIP := localIPv4()
	capturedAt := time.Now().UTC()
	if currentTime := filetimeTicksToTime(infoEx.CurrentTime); !currentTime.IsZero() {
		capturedAt = currentTime
	}

	return Status{
		Server:      c.serverName,
		User:        username,
		ClientIP:    clientIP,
		ClientName:  c.serverName,
		IdleSeconds: idleSeconds,
		Locked:      isLocked(infoEx.SessionFlags),
		CapturedAt:  capturedAt,
	}, nil
}

func currentUser() (string, error) {
	size := uint32(256)
	buffer := make([]uint16, size)
	if err := windows.GetUserNameEx(windows.NameSamCompatible, &buffer[0], &size); err == nil {
		return strings.TrimSpace(windows.UTF16ToString(buffer[:size])), nil
	}

	username := os.Getenv("USERNAME")
	userDomain := os.Getenv("USERDOMAIN")
	if username == "" {
		return "", fmt.Errorf("cannot resolve current username")
	}
	if userDomain != "" {
		return userDomain + `\` + username, nil
	}
	return username, nil
}

func queryCurrentSessionInfoEx() (*wtsInfoExLevel1, error) {
	var buffer uintptr
	var bytesReturned uint32

	result, _, callErr := procWTSQuerySessionInformation.Call(
		uintptr(wtsCurrentServerHandle),
		uintptr(wtsInfoCurrentSession),
		uintptr(wtsInfoSessionInfoEx),
		uintptr(unsafe.Pointer(&buffer)),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if result == 0 {
		if callErr != nil && callErr != windows.ERROR_SUCCESS {
			return nil, callErr
		}
		return nil, windows.GetLastError()
	}
	defer windows.WTSFreeMemory(buffer)

	info := (*wtsInfoEx)(unsafe.Pointer(buffer))
	if info.Level != 1 {
		return nil, fmt.Errorf("unexpected WTSSessionInfoEx level %d", info.Level)
	}
	return &info.Data.Level1, nil
}

func currentIdleSeconds() (int, error) {
	info := lastInputInfo{CbSize: uint32(unsafe.Sizeof(lastInputInfo{}))}
	result, _, callErr := procGetLastInputInfo.Call(uintptr(unsafe.Pointer(&info)))
	if result == 0 {
		if callErr != nil && callErr != windows.ERROR_SUCCESS {
			return 0, callErr
		}
		return 0, windows.GetLastError()
	}

	ticks := windows.DurationSinceBoot()
	currentMillis := uint64(ticks / time.Millisecond)
	if currentMillis < uint64(info.DwTime) {
		return 0, nil
	}
	return int((currentMillis - uint64(info.DwTime)) / 1000), nil
}

func isLocked(sessionFlags int32) bool {
	switch sessionFlags {
	case wtsSessionStateLock:
		return true
	case wtsSessionStateUnlock:
		return false
	default:
		return false
	}
}

func localIPv4() string {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}

	for _, address := range addresses {
		network, ok := address.(*net.IPNet)
		if !ok || network.IP.IsLoopback() {
			continue
		}
		ip4 := network.IP.To4()
		if ip4 == nil {
			continue
		}
		return ip4.String()
	}
	return ""
}

func filetimeTicksToTime(value int64) time.Time {
	if value <= 0 {
		return time.Time{}
	}
	const unixEpochOffset = 116444736000000000
	if value < unixEpochOffset {
		return time.Time{}
	}
	return time.Unix(0, (value-unixEpochOffset)*100).UTC()
}
