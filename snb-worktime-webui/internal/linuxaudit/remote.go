package linuxaudit

import (
	"fmt"
	"strings"
	"time"
)

func buildRemoteCommand(since time.Time, until time.Time) string {
	sinceText := shellQuote(since.Format("2006-01-02 15:04:05"))
	untilText := shellQuote(until.Format("2006-01-02 15:04:05"))

	return strings.Join([]string{
		"set -u",
		`SUDO=""`,
		`if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then SUDO="sudo -n "; fi`,
		`echo "__SECTION__:HOSTNAME"`,
		`(hostnamectl --static 2>/dev/null || hostname 2>/dev/null || true)`,
		`echo "__SECTION__:PASSWD"`,
		`(getent passwd 2>/dev/null || cat /etc/passwd 2>/dev/null || true)`,
		`echo "__SECTION__:LAST"`,
		`(sh -lc "${SUDO}last -F -w --time-format iso 2>/dev/null" || sh -lc "${SUDO}last -F -w 2>/dev/null" || true)`,
		`echo "__SECTION__:WHO"`,
		`(who -u 2>/dev/null || true)`,
		`echo "__SECTION__:JOURNAL"`,
		fmt.Sprintf(`(if command -v journalctl >/dev/null 2>&1; then sh -lc "${SUDO}journalctl --since %s --until %s --no-pager -o short-iso 2>/dev/null" | grep -E "sshd|sudo|su:|systemd-logind" || true; fi)`, sinceText, untilText),
		`echo "__SECTION__:AUTHLOG"`,
		`(for f in /var/log/auth.log /var/log/secure; do if sh -lc "${SUDO}test -r $f"; then echo "FILE:$f"; sh -lc "${SUDO}tail -n 4000 $f"; fi; done || true)`,
	}, "\n")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
