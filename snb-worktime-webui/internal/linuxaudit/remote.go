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
		`echo "__SECTION__:HISTORY"`,
		`((getent passwd 2>/dev/null || cat /etc/passwd 2>/dev/null || true) | while IFS=: read -r user _ uid _ _ home shell; do [ -n "$user" ] || continue; [ -n "$home" ] || continue; for hist in "$home/.bash_history" "$home/.zsh_history"; do if ${SUDO}test -r "$hist" 2>/dev/null; then echo "__HISTORY__:${user}:${hist}"; ${SUDO}tail -n 4000 "$hist" 2>/dev/null || true; fi; done; done || true)`,
		`echo "__SECTION__:TMUX"`,
		`(if command -v tmux >/dev/null 2>&1; then current_user="$(id -un 2>/dev/null || true)"; (getent passwd 2>/dev/null || cat /etc/passwd 2>/dev/null || true) | while IFS=: read -r user _ uid _ _ home shell; do [ -n "$user" ] || continue; [ -n "$uid" ] || continue; socket="/tmp/tmux-${uid}/default"; if [ -z "${SUDO}" ] && [ "$user" != "$current_user" ]; then continue; fi; if ! ${SUDO}test -S "$socket" 2>/dev/null; then continue; fi; echo "__TMUX__:${user}:${socket}"; ${SUDO}tmux -S "$socket" list-sessions -F '#{session_created}|#{session_activity}|#{session_attached}|#{session_name}' 2>/dev/null || true; done; fi)`,
	}, "\n")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
