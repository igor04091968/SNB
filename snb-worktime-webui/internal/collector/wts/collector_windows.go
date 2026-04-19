//go:build windows

package wts

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"snb-worktime-webui/internal/model"
)

const (
	wtsCurrentServerHandle = 0

	wtsInfoUserName      = 5
	wtsInfoClientName    = 10
	wtsInfoClientAddress = 14
	wtsInfoSessionInfoEx = 25

	wtsSessionStateUnknown = 0xffffffff

	addressFamilyINET  = 2
	addressFamilyINET6 = 23

	winstationNameLength = 32
	userNameLength       = 20
	domainLength         = 17
)

var (
	modWtsapi32                    = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformation = modWtsapi32.NewProc("WTSQuerySessionInformationW")
)

type collector struct {
	serverName string
}

type wtsClientAddressInfo struct {
	AddressFamily uint32
	Address       [20]byte
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
	WinStationName          [winstationNameLength + 1]uint16
	UserName                [userNameLength + 1]uint16
	DomainName              [domainLength + 1]uint16
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

func (c *collector) Snapshots() ([]model.Snapshot, error) {
	var sessionPtr *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(wtsCurrentServerHandle, 0, 1, &sessionPtr, &count); err != nil {
		return nil, fmt.Errorf("WTSEnumerateSessions: %w", err)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessionPtr)))

	sessions := unsafe.Slice(sessionPtr, int(count))
	fallbackCapturedAt := time.Now().UTC()

	snapshots := make([]model.Snapshot, 0, len(sessions))
	for _, session := range sessions {
		infoEx, err := querySessionInfoEx(session.SessionID)
		if err != nil {
			continue
		}

		username := utf16SliceToString(infoEx.UserName[:])
		if username == "" {
			username, _ = querySessionString(session.SessionID, wtsInfoUserName)
		}
		username = strings.TrimSpace(username)
		if username == "" {
			continue
		}

		clientName, _ := querySessionString(session.SessionID, wtsInfoClientName)
		clientIP, _ := queryClientIP(session.SessionID)

		capturedAt := filetimeTicksToTime(infoEx.CurrentTime)
		if capturedAt.IsZero() {
			capturedAt = fallbackCapturedAt
		}

		snapshots = append(snapshots, model.Snapshot{
			Server:      c.serverName,
			User:        username,
			SessionID:   fmt.Sprintf("%d", session.SessionID),
			State:       mapState(uint32(session.State)),
			IdleSeconds: idleSeconds(infoEx.LastInputTime, infoEx.CurrentTime),
			ClientIP:    clientIP,
			ClientName:  strings.TrimSpace(clientName),
			CapturedAt:  capturedAt,
			LogonTime:   filetimeTicksToTime(infoEx.LogonTime),
		})
	}

	return snapshots, nil
}

func querySessionInfoEx(sessionID uint32) (*wtsInfoExLevel1, error) {
	buffer, _, err := querySessionInformation(sessionID, wtsInfoSessionInfoEx)
	if err != nil {
		return nil, err
	}
	defer windows.WTSFreeMemory(buffer)

	info := (*wtsInfoEx)(unsafe.Pointer(buffer))
	if info.Level != 1 {
		return nil, fmt.Errorf("unexpected WTSSessionInfoEx level %d", info.Level)
	}
	return &info.Data.Level1, nil
}

func querySessionString(sessionID uint32, infoClass uint32) (string, error) {
	buffer, _, err := querySessionInformation(sessionID, infoClass)
	if err != nil {
		return "", err
	}
	defer windows.WTSFreeMemory(buffer)

	if buffer == 0 {
		return "", nil
	}
	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(buffer))), nil
}

func queryClientIP(sessionID uint32) (string, error) {
	buffer, _, err := querySessionInformation(sessionID, wtsInfoClientAddress)
	if err != nil {
		return "", err
	}
	defer windows.WTSFreeMemory(buffer)

	address := (*wtsClientAddressInfo)(unsafe.Pointer(buffer))
	return parseClientAddress(address), nil
}

func querySessionInformation(sessionID uint32, infoClass uint32) (uintptr, uint32, error) {
	var buffer uintptr
	var bytesReturned uint32

	result, _, callErr := procWTSQuerySessionInformation.Call(
		uintptr(wtsCurrentServerHandle),
		uintptr(sessionID),
		uintptr(infoClass),
		uintptr(unsafe.Pointer(&buffer)),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if result == 0 {
		if callErr != windows.ERROR_SUCCESS && callErr != nil {
			return 0, 0, callErr
		}
		return 0, 0, windows.GetLastError()
	}

	return buffer, bytesReturned, nil
}

func parseClientAddress(address *wtsClientAddressInfo) string {
	if address == nil {
		return ""
	}

	switch address.AddressFamily {
	case addressFamilyINET:
		return net.IP(address.Address[2:6]).String()
	case addressFamilyINET6:
		return net.IP(address.Address[:16]).String()
	default:
		return ""
	}
}

func mapState(state uint32) string {
	switch state {
	case windows.WTSActive:
		return "active"
	case windows.WTSConnected:
		return "connected"
	case windows.WTSDisconnected:
		return "disconnected"
	case windows.WTSIdle:
		return "idle"
	case windows.WTSListen:
		return "listen"
	case windows.WTSShadow:
		return "shadow"
	case windows.WTSReset:
		return "reset"
	case windows.WTSDown:
		return "down"
	case windows.WTSInit:
		return "init"
	case windows.WTSConnectQuery:
		return "connect-query"
	case wtsSessionStateUnknown:
		return "unknown"
	default:
		return fmt.Sprintf("state-%d", state)
	}
}

func idleSeconds(lastInputTicks int64, currentTicks int64) int {
	if lastInputTicks <= 0 || currentTicks <= 0 || currentTicks < lastInputTicks {
		return 0
	}
	return int((currentTicks - lastInputTicks) / 10_000_000)
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

func utf16SliceToString(value []uint16) string {
	limit := 0
	for limit < len(value) && value[limit] != 0 {
		limit++
	}
	return string(utf16.Decode(value[:limit]))
}
