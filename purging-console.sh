#!/usr/bin/env bash
#
# Purging Management Console
# ------------------------------------------------------------
# Enterprise-grade interactive console for managing scheduled
# file purging / log truncation on Linux hosts.
#
#   - First-run guided setup (installs a systemd service - purge pass interval is a setting)
#   - Add / edit / remove purge paths
#   - Per-path retention: hours / days / weeks / months / size / schedule
#   - Storage-impact preview before you commit a retention
#   - Enable / disable individual paths or the whole service
#   - Dashboard: live storage, per-path status, last-purge time
#   - Health check, configuration backup/restore, statistics, dry-run
#
# Configs live under /etc/darshan/purging
# CLI:  --watch --worker --status --health --validate --dry-run
#       --backup [file] --restore <file> --stats --version --debug
#       --verbose --repair --list --export <file> --import <file>
#       add <path> <ret> | purge
# ------------------------------------------------------------

set -u

# ============================================================
# SECTION: Constants & Global State
# ============================================================
readonly APP_NAME="Purging Management Console"
readonly APP_VERSION="2.6.12"
readonly CONFIG_SCHEMA_VERSION=2
readonly CONF_DIR="/etc/darshan/purging"
readonly PATHS_DIR="${CONF_DIR}/paths.d"
readonly BACKUP_DIR="${CONF_DIR}/backups"
readonly MARKER="${CONF_DIR}/.installed"
readonly LOCK_FILE="${CONF_DIR}/.worker.lock"
readonly LOG_FILE="/var/log/purging-console.log"
readonly SELF_INSTALL_PATH="/usr/local/bin/purgingconsole"
readonly SERVICE_NAME="purging-console"
readonly SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
readonly TIMER_FILE="/etc/systemd/system/${SERVICE_NAME}.timer"
readonly REQUIRED_DEPS=(systemctl find awk date stat truncate df sha1sum flock)

# Runtime flags (mutable globals - intentionally isolated to this block)
DEBUG_MODE=0
VERBOSE_MODE=0
DRY_RUN_MODE=0

# ============================================================
# SECTION: Settings - every value the purge engine uses, editable from the console
#          (menu 10, or --settings / --set KEY VALUE / --unset KEY). Saved in engine.conf.
# ============================================================
SETTINGS_FILE="${CONF_DIR}/engine.conf"
# The one fixed list: operating-system folders. Deleting files in these can break the server and they
# never hold application logs, so they stay protected no matter what the settings say.
readonly PG_PROTECT_FLOOR=( "/" "/etc" "/usr" "/bin" "/sbin" "/lib" "/lib64" "/boot" "/dev" "/proc" "/sys" "/run" )

# KEY <tab> type <tab> default <tab> group <tab> label      (list values: items separated by |)
# types: dur (30s/15m/2h/1d)  pct  bool  size (64MB/1GB)  hhmm (23:55)  path  list:path  list:name  list:regex
#        dirname (a folder name, or off)  copyname (copy-name format: {name} {ext} + date codes)  url (https://...)
SETTINGS_REGISTRY=$(cat <<'REG'
PG_GRACE_SEC	dur	3600	Rotation	Hold each rotated copy this long, then delete it (paths can override)
PG_DISK_EMERGENCY_PCT	pct	90	Rotation	Disk use at which a fully-read copy may go before its hold ends
PG_COPY_DIR	dirname	purged	Rotation	Folder (inside the log's own folder) that holds the rotated copies; off = keep them beside the log
PG_COPY_NAME	copyname	{name}_delete-at_%d-%b-%Y_at_%I-%M-%S-%p-%Z{ext}	Rotation	Name of a rotated copy: {name} {ext} and date codes (%d %b %Y %I %M %S %p %Z) for its delete time
PG_ALLOW_TRUNCATE	bool	0	Rotation	Allow emptying a file in place when it cannot be rotated (paths can override)
PG_ALLOW_BEHIND	bool	1	Rotation	Rotate while readers are still behind (they drain the old copy)
PG_MAX_BEHIND	size	67108864	Rotation	Never rotate while a reader is more than this far behind
PG_REPLAY_MARGIN	size	268435456	Rotation	Free disk to keep when replaying data a crashed reader missed
PG_ASIDE_KEEP_SEC	dur	86400	Rotation	Keep the safety copy made before an in-place empty this long
PG_ASIDE_MARGIN	size	1073741824	Rotation	Make that safety copy only if this much disk stays free
PG_CATCHUP_SEC	dur	20	Timing	Wait up to this long for readers to reach the end
PG_VERIFY_SEC	dur	15	Timing	Wait up to this long for writers to reopen after a rotation
PG_RECENT_WRITE_SEC	dur	60	Timing	A file nobody holds open but written this recently may have a writer about to reopen it
PG_RETRY_SEC	dur	60	Timing	Retry a file that had to be skipped after
PG_PASS_SEC	dur	5	Timing	Background service: purge pass every
PG_TICK_SEC	dur	1	Timing	Background service: check readers of rotated copies every
PG_DAILY_AT	hhmm	0000	Timing	Daily paths ("midnight" retention) rotate at this time of day
PG_QUIET_PREFIXES	list:path	/var/ossec/logs/	Quiet window	Folders where nothing is touched during the quiet window
PG_QUIET_FROM	hhmm	2355	Quiet window	Quiet window starts at
PG_QUIET_TO	hhmm	0010	Quiet window	Quiet window ends at
PG_PROTECT_PATHS	list:path	/root|/usr/local|/var/ossec/etc|/var/ossec/bin|/var/ossec/ruleset|/var/ossec/framework|/var/ossec/queue|/var/ossec/active-response|/var/ossec/wodles|/var/ossec/lib|/var/ossec/agentless|/var/lib/rsyslog|/var/spool/rsyslog|/var/log/journal|/run/log/journal|/var/lib/wazuh-indexer|/var/lib/opensearch|/var/lib/elasticsearch|/var/lib/docker|/var/lib/containerd|/var/lib/clickhouse|/var/lib/kafka|/var/lib/mongodb|/var/lib/postgresql|/var/lib/mysql|/var/lib/redis	Protection	Folders never touched, with everything inside them
PG_PROTECT_NAMES	list:name	*.pos|*.qi|*.journal|*.journal~	Protection	File names never touched, wherever they are
PG_REFUSE_WHOLE	list:path	/home|/home/*|/var|/var/lib|/opt|/srv|/data|/mnt|/tmp	Protection	Folders that cannot be added as a whole (add a folder inside them)
PG_READERS	list:name	tail|filebeat|promtail|vector|fluent-bit|logstash	Readers	Other programs that read logs to the end (besides rsyslog, Fluentd, Wazuh)
DET_FLUENTD_CONFS	list:path	/etc/fluent/fluentd.conf|/etc/fluent/fluent.conf|/etc/fluentd/*.conf|/etc/td-agent/td-agent.conf|/etc/fluent/conf.d/*.conf|/etc/td-agent/conf.d/*.conf	Readers	Fluentd config files (running fluentd configs are always read too)
DET_FLUENTD_SKIP	list:name	*.bak|*.new|*.orig|*-old.conf|*.disabled	Readers	Fluentd config files to ignore
DET_RSYSLOG_FILES	list:path	/etc/rsyslog.conf|/etc/rsyslog.d/*.conf	Readers	rsyslog config files
DET_WAZUH_CONF	path	/var/ossec/etc/ossec.conf	Readers	Wazuh config file
DET_WAZUH_STATUS	path	/var/ossec/queue/logcollector/file_status.json	Readers	Wazuh logcollector position file
DET_LOGROTATE_FILES	list:path	/etc/logrotate.conf|/etc/logrotate.d/*	Readers	logrotate config files (for conflict warnings)
PG_ROTATED_EXTRA	list:regex		File names	Extra regex for already-rotated file names (besides .gz .1 .old .sum ...)
PG_DATED_EXTRA	list:regex		File names	Extra regex for date-named file names (besides 20261029 / 2026-10-29)
PG_HELD_ROOTS	list:path	/var/log|/var/ossec/logs|/opt|/data|/srv|/home/*/*	Reports	Folders checked for deleted-but-still-open files
PG_HELD_SKIP	list:name	*/.cache/*|*/.mozilla/*|*/snap/*|*.sqlite*|*/.vscode-server/*	Reports	Paths skipped in that check
PG_UPDATE_URL	url	https://raw.githubusercontent.com/darshanfct/purgingconsole-releases/main	Update	Where --update looks for new versions (the raw files of the releases repo: purging-console.sh, CHANGELOG.md)
PG_AUTO_UPDATE	bool	0	Update	Install newer versions by itself once a day (off: only when you run --update)
PG_AUTO_UPDATE_AT	hhmm	0300	Update	Time of day for the automatic update check (server time)
REG
)
declare -A SETTINGS_ENV=() SETTINGS_FROM=()
SETTINGS_MTIME=""

settings_keys() { awk -F'\t' 'NF>=4 && $1!="" {print $1}' <<<"$SETTINGS_REGISTRY"; }
settings_field() { awk -F'\t' -v k="$1" -v n="$2" '$1==k {print $n; exit}' <<<"$SETTINGS_REGISTRY"; }  # 2 type 3 default 4 group 5 label
list_items() {   # never glob-expanded: an item like *.pos must not turn into a file name from the current folder
  local v="${!1:-}" i; local -a _li=()
  IFS='|' read -r -a _li <<<"$v"
  for i in ${_li[@]+"${_li[@]}"}; do [ -n "$i" ] && printf '%s\n' "$i"; done; return 0
}
# list_glob <KEY> - the list's items with shell globs expanded to existing files
list_glob() { local i m; while IFS= read -r i; do for m in $i; do [ -e "$m" ] && printf '%s\n' "$m"; done; done < <(list_items "$1"); return 0; }

# settings_normalize <key> <raw> - echoes the stored form, or an error message with rc 1
settings_normalize() {
  local key="$1" raw="$2" t v out="" item re n
  t=$(settings_field "$key" 2)
  [ -n "$t" ] || { echo "unknown setting '$key'"; return 1; }
  raw="${raw#"${raw%%[![:space:]]*}"}"; raw="${raw%"${raw##*[![:space:]]}"}"
  case "$t" in
    dur)  v=$(parse_duration_sec "$raw") || { echo "use a time like 30s, 15m, 2h, 1d"; return 1; }
          # the service loop and the writer check need a real interval: 0 would spin a CPU core
          case "$key" in PG_TICK_SEC|PG_PASS_SEC|PG_VERIFY_SEC) [ "$v" -ge 1 ] || { echo "use at least 1s"; return 1; };; esac
          echo "$v";;
    pct)  v="${raw%\%}"; [[ "$v" =~ ^[0-9]{1,3}$ ]] && v=$(( 10#$v )) && [ "$v" -ge 1 ] && [ "$v" -le 100 ] || { echo "use a percentage from 1 to 100"; return 1; }; echo "$v";;
    bool) case "${raw,,}" in on|yes|1|true|enable|enabled) echo 1;; off|no|0|false|disable|disabled) echo 0;; *) echo "use on or off"; return 1;; esac;;
    size) [[ "${raw^^}" =~ ^([0-9]+)[[:space:]]*(B|K|KB|M|MB|G|GB)?$ ]] || { echo "use a size like 64MB or 1GB"; return 1; }
          n=$(( 10#${BASH_REMATCH[1]} ))       # 10#: "08" is eight, not a bad octal number that stops the script
          case "${BASH_REMATCH[2]}" in K|KB) n=$(( n * 1024 ));; M|MB) n=$(( n * 1048576 ));; G|GB) n=$(( n * 1073741824 ));; esac
          echo "$n";;
    hhmm) [[ "$raw" =~ ^([01]?[0-9]|2[0-3]):?([0-5][0-9])$ ]] || { echo "use a time of day like 23:55"; return 1; }
          printf '%02d%02d\n' "$((10#${BASH_REMATCH[1]}))" "$((10#${BASH_REMATCH[2]}))";;
    url)  [[ "$raw" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~%/+-]*)?$ ]] || { echo "use an https:// address (no spaces or quotes)"; return 1; }
          echo "${raw%/}";;
    path) [[ "$raw" = /* ]] || { echo "use an absolute path"; return 1; }
          [[ "$raw" == *[\"$'\n\r']* ]] && { echo "the path contains a quote or a line break"; return 1; }
          echo "$raw";;
    dirname)
          case "${raw,,}" in off|none|no) echo off; return 0;; esac
          [[ "$raw" =~ ^[A-Za-z0-9._-]+$ ]] && [ "$raw" != "." ] && [ "$raw" != ".." ] \
            || { echo "use a plain folder name like purged (letters, digits . _ -), or off"; return 1; }
          echo "$raw";;
    copyname)
          [[ "$raw" == *[\"$'\n\r\t']* ]] && { echo "the name contains a quote, tab or line break"; return 1; }
          [[ "$raw" == *"{name}"* ]] || { echo "the name must contain {name} (the log's own name), e.g. {name}_delete-at_%d-%b-%Y{ext}"; return 1; }
          [[ "$raw" == */* ]] && { echo "the name cannot contain /"; return 1; }
          v=$(LC_ALL=C date -d @0 +"$raw" 2>/dev/null) || { echo "the date codes in it are not valid"; return 1; }
          [[ "$v" == */* ]] && { echo "a date code in it produces a / (e.g. %D or %x) - use %d-%m-%y instead"; return 1; }
          [[ "$v" =~ \.purge-[0-9]+$ ]] && { echo "the name cannot end in .purge-<digits>"; return 1; }
          echo "$raw";;
    list:*)
      local -a _items=()
      IFS='|' read -r -a _items <<<"$raw"           # split without glob expansion
      for item in ${_items[@]+"${_items[@]}"}; do
        [[ "$item" == *[\"$'\n\r']* ]] && { echo "'$item' contains a quote or a line break"; return 1; }
        item="${item#"${item%%[![:space:]]*}"}"; item="${item%"${item##*[![:space:]]}"}"
        [ -n "$item" ] || continue
        case "$t" in
          list:path)  [[ "$item" = /* ]] || { echo "'$item' is not an absolute path"; return 1; };;
          list:regex) re="$item"; [[ "" =~ $re ]]; [ $? -eq 2 ] && { echo "'$item' is not a valid regular expression"; return 1; };;
        esac
        out+="${out:+|}$item"
      done
      echo "$out";;
  esac
}

# settings_show <key> [value] - human form of a value
settings_show() {
  local key="$1" v t
  if [ $# -ge 2 ]; then v="$2"; else v="${!key:-}"; fi
  t=$(settings_field "$key" 2)
  case "$t" in
    dur)  human_secs "$v";;
    pct)  echo "${v}%";;
    bool) [ "$v" = 1 ] && echo on || echo off;;
    size) human "$v";;
    hhmm) echo "${v:0:2}:${v:2:2}";;
    list:*) local n; n=$(list_items "$key" | wc -l); [ "$#" -ge 2 ] && n=$(tr '|' '\n' <<<"$v" | grep -c .)
            local first="${v%%|*}"; [ "$n" -eq 0 ] && echo "(none)" || { [ "$n" -gt 1 ] && echo "$first  (+$(( n - 1 )) more)" || echo "$first"; };;
    *)    echo "$v";;
  esac
}

# settings_load - defaults, then engine.conf, then (for testing) values already set in the environment
settings_load() {
  local key def line k v norm
  if [ -z "${SETTINGS_ENV_CAPTURED:-}" ]; then
    while IFS= read -r key; do [ -n "${!key+x}" ] && SETTINGS_ENV[$key]="${!key}"; done < <(settings_keys)
    SETTINGS_ENV_CAPTURED=1
  fi
  while IFS= read -r key; do
    printf -v "$key" '%s' "$(settings_field "$key" 3)"; SETTINGS_FROM[$key]=default
  done < <(settings_keys)
  if [ -r "$SETTINGS_FILE" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      line="${line%$'\r'}"                         # a file edited on Windows must not keep a stray \r
      [[ "$line" =~ ^[[:space:]]*([A-Z_]+)=(.*)$ ]] || continue
      k=${BASH_REMATCH[1]}; v=${BASH_REMATCH[2]}
      v="${v#\"}"; v="${v%\"}"
      [ -n "$(settings_field "$k" 2)" ] || continue
      if norm=$(settings_normalize "$k" "$v"); then printf -v "$k" '%s' "$norm"; SETTINGS_FROM[$k]=file
      else log_warn "engine.conf: ignoring $k ($norm)"; fi
    done < "$SETTINGS_FILE"
    SETTINGS_MTIME=$(stat -c '%y %i' "$SETTINGS_FILE" 2>/dev/null)   # ns + inode: two saves in one second still differ
  else
    SETTINGS_MTIME=""
  fi
  for k in "${!SETTINGS_ENV[@]}"; do
    if norm=$(settings_normalize "$k" "${SETTINGS_ENV[$k]}"); then printf -v "$k" '%s' "$norm"; SETTINGS_FROM[$k]=environment; fi
  done
  # derived
  BLOCKED_PATHS=( "${PG_PROTECT_FLOOR[@]}" )
  while IFS= read -r v; do BLOCKED_PATHS+=( "${v%/}" ); done < <(list_items PG_PROTECT_PATHS)
  return 0
}

# settings_reload_if_changed - the background service picks up console changes without a restart
settings_reload_if_changed() {
  local m; m=$(stat -c '%y %i' "$SETTINGS_FILE" 2>/dev/null)
  if [ "$m" != "$SETTINGS_MTIME" ]; then settings_load; log_info "settings reloaded from $SETTINGS_FILE"; fi
}

# settings_save <key> <normalized value | ""=back to default> - rewrites engine.conf atomically
settings_save() {
  local key="$1" val="$2" tmp k
  mkdir -p "$CONF_DIR" && chmod 700 "$CONF_DIR" 2>/dev/null
  # Start from what is on disk now. Another console or a --set may have saved since this process loaded;
  # writing the file from this process's memory would silently undo those changes.
  settings_load
  tmp="$SETTINGS_FILE.tmp.$$"
  {
    echo "# Purging Management Console - engine settings (edit from the console: purgingconsole → c)"
    while IFS= read -r k; do
      [ "$k" = "$key" ] && continue
      [ "${SETTINGS_FROM[$k]:-}" = file ] && printf '%s="%s"\n' "$k" "${!k}"
    done < <(settings_keys)
    if [ -n "$val" ] && [ "$val" != "$(settings_field "$key" 3)" ]; then printf '%s="%s"\n' "$key" "$val"; fi
  } > "$tmp" && chmod 600 "$tmp" && mv -f "$tmp" "$SETTINGS_FILE" || { rm -f "$tmp"; return 1; }
  settings_load
  log_info "setting $key = ${val:-(default)}"
}

# settings_set <key> <raw value|default> - validate + save (CLI and menu)
settings_set() {
  local key="$1" raw="$2" norm
  [ -n "$(settings_field "$key" 2)" ] || { echo "unknown setting '$key' (see: purgingconsole --settings)"; return 1; }
  if [ "$raw" = "default" ] || [ -z "$raw" ]; then settings_save "$key" ""; return; fi
  norm=$(settings_normalize "$key" "$raw") || { echo "invalid value for $key: $norm"; return 1; }
  settings_save "$key" "$norm"
}

settings_print() {
  local key t def grp label last="" src
  while IFS=$'\t' read -r key t def grp label; do
    [ -n "$key" ] || continue
    [ "$grp" != "$last" ] && { echo; echo "[$grp]"; last=$grp; }
    src=${SETTINGS_FROM[$key]:-default}
    printf "  %-22s = %-28s %s\n" "$key" "$(settings_show "$key")" "$([ "$src" = default ] && echo "(default)" || echo "(set: $src, default $(settings_show "$key" "$def"))")"
    printf "  %-22s   %s%s%s\n" "" "$C_DIM" "$label" "$C_RESET"
    [[ "$t" == list:* ]] && [ "$(list_items "$key" | wc -l)" -gt 1 ] && list_items "$key" | sed 's/^/                             · /'
  done <<<"$SETTINGS_REGISTRY"
  return 0
}

# ============================================================
# SECTION: Terminal Presentation (colors, glyphs)
# ============================================================
if [ -t 1 ]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m';  C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'; C_MAGENTA=$'\033[35m'; C_CYAN=$'\033[36m'; C_GREY=$'\033[90m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""
  C_BLUE=""; C_MAGENTA=""; C_CYAN=""; C_GREY=""
fi
readonly BULLET=$'●'
readonly CHECK=$'✓'
readonly CROSS=$'✗'
readonly WARN_GLYPH=$'⚠'

dot()   { printf "%s%s%s" "$1" "$BULLET" "$C_RESET"; }        # dot <color>
badge() { printf "%s[%s]%s" "$1" "$2" "$C_RESET"; }           # badge <color> <text>

# menu_section <title> - subtle group heading used in main_menu
menu_section() { printf "\n  ${C_DIM}%s${C_RESET}\n" "$1"; }

# menu_row <key> <label> - single aligned menu entry; key column is a fixed
# 4 chars wide so color codes never interfere with column alignment.
menu_row() { printf "   ${C_CYAN}%2s${C_RESET}  %s\n" "$1" "$2"; }

# Terminal width, safely defaulted for non-interactive / narrow contexts
term_width() {
  local w
  w=$(tput cols 2>/dev/null) || w=80
  [ -z "$w" ] && w=80
  echo "$w"
}

hr() {  # hr [char]
  local ch="${1:--}" w
  w=$(term_width); [ "$w" -gt 100 ] && w=100
  printf '%*s\n' "$w" '' | tr ' ' "$ch"
}

# ============================================================
# SECTION: Logging (leveled, timestamped)
# ============================================================
# log <LEVEL> <message>   LEVEL: INFO|WARN|ERROR|DEBUG|SUCCESS
log() {
  local level="$1"; shift
  local msg="$*"
  [ "$level" = "DEBUG" ] && [ "$DEBUG_MODE" -ne 1 ] && return 0
  printf '%s [%-7s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$msg" >> "$LOG_FILE" 2>/dev/null
}
log_info()    { log "INFO"    "$*"; }
log_warn()    { log "WARNING" "$*"; }
log_error()   { log "ERROR"   "$*"; }
log_debug()   { log "DEBUG"   "$*"; }
log_success() { log "SUCCESS" "$*"; }

# ============================================================
# SECTION: Generic Helpers
# ============================================================
pause() { echo; read -rp "${C_DIM}Press Enter to continue...${C_RESET}" _; }
# menu_eof - a menu prompt got no input at all (no terminal: cron, a pipe that ran out): stop instead of
# printing "Invalid choice" forever
menu_eof() { echo; echo "no more input - leaving the menu" >&2; exit 0; }

confirm() {
  local prompt="${1:-Are you sure?}" ans
  read -rp "$prompt ${C_DIM}[y/N]${C_RESET} " ans
  [[ "$ans" =~ ^[Yy]$ ]]
}

die() { echo "${C_RED}error:${C_RESET} $*" >&2; log_error "$*"; exit 1; }

info_msg()    { echo "${C_CYAN}${C_BOLD}i${C_RESET}  $*"; }
warn_msg()    { echo "${C_YELLOW}${WARN_GLYPH}${C_RESET}  $*"; }
error_msg()   { echo "${C_RED}${CROSS}${C_RESET}  $*"; }
success_msg() { echo "${C_GREEN}${CHECK}${C_RESET}  $*"; }

human() {
  local b=${1:-0}
  if numfmt --to=iec --suffix=B "$b" 2>/dev/null; then return; fi
  if   [ "$b" -ge 1073741824 ]; then printf "%dGiB\n" $(( b / 1073741824 ))
  elif [ "$b" -ge 1048576 ];    then printf "%dMiB\n" $(( b / 1048576 ))
  elif [ "$b" -ge 1024 ];       then printf "%dKiB\n" $(( b / 1024 ))
  else                               echo "${b}B"
  fi
}

rel_time() {
  local then=${1:-0} now diff
  if [ -z "$then" ] || [ "$then" = "0" ]; then echo "never"; return; fi
  now=$(date +%s); diff=$(( now - then ))
  if   [ "$diff" -lt 60 ];    then echo "${diff}s ago"
  elif [ "$diff" -lt 3600 ];  then echo "$(( diff / 60 ))m ago"
  elif [ "$diff" -lt 86400 ]; then echo "$(( diff / 3600 ))h ago"
  else echo "$(( diff / 86400 ))d ago"; fi
}

unit_to_min() {  # <value> <unit>  ->  minutes (mb: raw value passed through)
  local v=$1 u=$2
  [[ "$v" =~ ^[0-9]+$ ]] && v=$(( 10#$v )) || v=0
  case "$u" in
    hours)  echo $(( v * 60 ));;
    days)   echo $(( v * 1440 ));;
    weeks)  echo $(( v * 10080 ));;
    months) echo $(( v * 43200 ));;   # 30-day month
    mb)     echo "$v";;               # raw MB value; handled separately in worker
    midnight) echo "1440";;           # placeholder; worker uses calendar-date logic
    *)      echo $(( v * 1440 ));;
  esac
}

unit_short() { case "$1" in hours) echo h;; days) echo d;; weeks) echo w;; months) echo mo;; mb) echo mb;; midnight) echo "@${PG_DAILY_AT:0:2}:${PG_DAILY_AT:2:2}";; *) echo d;; esac; }

path_id() { printf '%s' "$1" | sha1sum | cut -c1-12; }

# parse_retention "7d" -> "7 days"  |  "2h" -> "2 hours"  |  "3w" -> "3 weeks"  |  "1m" -> "1 months"
parse_retention() {
  local ret="$1"
  # numbers are read as decimal (10#): bash would take "08" as a bad octal number and stop the script, and
  # "010" as eight. 0 is refused: a path with retention 0 would rotate / delete on every pass.
  if [[ "$ret" =~ ^([0-9]{1,9})(h|d|w|m)$ ]]; then
    local v=$(( 10#${BASH_REMATCH[1]} )) s="${BASH_REMATCH[2]}" u
    [ "$v" -ge 1 ] || return 1
    case "$s" in h) u="hours";; d) u="days";; w) u="weeks";; m) u="months";; esac
    echo "$v $u"; return 0
  fi
  case "$ret" in midnight|daily|@00:00) echo "1 midnight"; return 0;; esac          # rotate once a day (at setting PG_DAILY_AT)
  if [[ "$ret" =~ ^([0-9]{1,9})(mb|MB|M)$ ]] && [ $(( 10#${BASH_REMATCH[1]} )) -ge 1 ]; then echo "$(( 10#${BASH_REMATCH[1]} )) mb"; return 0; fi  # rotate above N MB
  return 1
}

# is_positive_int <value> -> validates a whole number >= 1
is_positive_int() { [[ "$1" =~ ^[0-9]{1,9}$ ]] && [ $(( 10#$1 )) -ge 1 ]; }   # callers store $(( 10#value ))

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "${C_YELLOW}This action needs root. Re-running with sudo...${C_RESET}"
    exec sudo -E bash "$0" "$@"
  fi
}

# is_safe_path <path> -> prints reason and returns 1 on rejection.
# Guards against: relative paths, protected system dirs, and symlinks
# that resolve outside of what the admin thinks they're targeting.
is_safe_path() {
  local p="$1" b resolved
  [[ "$p" = /* ]] || { echo "Path must be absolute (start with /)."; return 1; }
  p="${p%/}"; [ -z "$p" ] && p="/"
  # whole folders on the "cannot be added as a whole" list (setting PG_REFUSE_WHOLE) are refused
  local w
  while IFS= read -r w; do
    if det_glob_match "$p" "${w%/}"; then echo "Refusing to manage the whole of $p - add the folder that holds the logs (setting: PG_REFUSE_WHOLE)."; return 1; fi
  done < <(list_items PG_REFUSE_WHOLE)
  for b in "${BLOCKED_PATHS[@]}"; do
    if [ "$p" = "$b" ] || [[ "$p" == "$b/"* ]]; then echo "Refusing to manage a protected system path: $b"; return 1; fi
  done
  if [ -e "$p" ]; then
    resolved=$(readlink -f "$p" 2>/dev/null) || resolved="$p"
    if [ "$resolved" != "$p" ]; then
      for b in "${BLOCKED_PATHS[@]}"; do
        if [ "$resolved" = "$b" ] || [[ "$resolved" == "$b/"* ]]; then
          echo "Refusing: '$p' resolves (via symlink) to protected path $resolved"; return 1
        fi
      done
    fi
  fi
  return 0
}

# safe_target <folder> - the folder a path config will actually search (after splitting off the file name).
# Echoes its canonical form (no "..", no symlinks) or, with rc 1, why it is refused. Checking only what the
# user typed is not enough: "/*.log" passes as a string but would make the whole disk ("/") the target.
safe_target() {
  local d="${1%/}" c msg
  [ -n "$d" ] || d="/"
  [[ "$d" = /* ]] || { echo "Path must be absolute (start with /)."; return 1; }
  [[ "$d" == *[\"$'\n\r']* ]] && { echo "The path contains a quote or a line break."; return 1; }
  c=$(realpath -m -- "$d" 2>/dev/null) || c="$d"
  [ "$c" = "/" ] && { echo "Refusing to manage the whole disk (/) - add the folder that holds the logs."; return 1; }
  msg=$(is_safe_path "$c") || { echo "$msg"; return 1; }
  if [ "$c" != "$d" ]; then msg=$(is_safe_path "$d") || { echo "$msg"; return 1; }; fi
  echo "$c"
}

# safe_pattern <pattern> - a file-name pattern: no folder part, no quote or line break
safe_pattern() {
  [ -n "$1" ] || { echo "The file pattern is empty."; return 1; }
  [[ "$1" == */* ]] && { echo "The file pattern cannot contain '/' (put the folder in the path)."; return 1; }
  [[ "$1" == *[\"$'\n\r']* ]] && { echo "The file pattern contains a quote or a line break."; return 1; }
  return 0
}

# ============================================================
# SECTION: Dependency & Environment Validation
# ============================================================
check_dependencies() {
  local missing=() d
  for d in "${REQUIRED_DEPS[@]}"; do
    command -v "$d" >/dev/null 2>&1 || missing+=("$d")
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    printf '%s\n' "${missing[@]}"
    return 1
  fi
  return 0
}

# ============================================================
# SECTION: Path Config Read/Write (with validation)
# ============================================================
# Each path is a small sourceable conf file in $PATHS_DIR/<id>.conf

# validate_conf_values - reject malformed/corrupted config content before use
validate_conf_values() {
  local target="$1" pattern="$2" value="$3" unit="$4" enabled="$5"
  [[ "$target" = /* ]] || { echo "TARGET_PATH not absolute: '$target'"; return 1; }
  [ "${target%/}" != "" ] || { echo "TARGET_PATH is the whole disk (/)"; return 1; }
  [[ "$target" == *[\"$'\n\r']* ]] && { echo "TARGET_PATH contains a quote or line break"; return 1; }
  safe_pattern "$pattern" >/dev/null || { echo "PATTERN not allowed: '$pattern'"; return 1; }
  [[ "$value" =~ ^[1-9][0-9]{0,8}$ ]] || { echo "RETENTION_VALUE must be a whole number 1 or more: '$value'"; return 1; }
  case "$unit" in hours|days|weeks|months|mb|midnight) ;; *) echo "unknown RETENTION_UNIT: '$unit'"; return 1;; esac
  [[ "$enabled" =~ ^[01]$ ]] || { echo "ENABLED must be 0 or 1: '$enabled'"; return 1; }
  return 0
}

write_conf() {
  # write_conf <id> <target> <pattern> <value> <unit> <enabled> <last_purge> <last_freed>
  local id=$1 target=$2 pattern=$3 value=$4 unit=$5 enabled=$6 lp=$7 lf=$8
  local err
  if ! err=$(validate_conf_values "$target" "$pattern" "$value" "$unit" "$enabled"); then
    log_error "refusing to write invalid config for $id: $err"
    echo "invalid config values: $err" >&2
    return 1
  fi
  mkdir -p "$PATHS_DIR" 2>/dev/null
  chmod 700 "$CONF_DIR" "$PATHS_DIR" 2>/dev/null
  local tmp="$PATHS_DIR/.$id.conf.tmp.$$"
  cat > "$tmp" <<EOF
# Purging Management Console - path configuration
SCHEMA_VERSION=${CONFIG_SCHEMA_VERSION}
TARGET_PATH="$target"
PATTERN="$pattern"
RETENTION_VALUE=$value
RETENTION_UNIT="$unit"
ENABLED=$enabled
LAST_PURGE=$lp
LAST_FREED=$lf
EOF
  local wrc=$?
  # optional per-path hold for rotated copies (seconds); kept across rewrites of this config
  if [ "$wrc" -eq 0 ] && [[ "${HOLD_SEC:-}" =~ ^[0-9]+$ ]]; then echo "HOLD_SEC=$HOLD_SEC" >> "$tmp" || wrc=1; fi
  if [ "$wrc" -eq 0 ] && [[ "${PATH_ALLOW_TRUNCATE:-}" =~ ^[01]$ ]]; then echo "PATH_ALLOW_TRUNCATE=$PATH_ALLOW_TRUNCATE" >> "$tmp" || wrc=1; fi
  if [ "$wrc" -ne 0 ]; then rm -f "$tmp"; return 1; fi
  chmod 600 "$tmp" 2>/dev/null
  mv -f "$tmp" "$PATHS_DIR/$id.conf"   # atomic replace - avoids torn reads by the worker/watcher
}

list_confs() { ls -1 "$PATHS_DIR"/*.conf 2>/dev/null; }

count_confs() { list_confs | wc -l | tr -d ' '; }

# conf locking: the service writes a path's bookkeeping back after each pass, and the console / CLI edit,
# disable and remove paths. Both take this lock, so neither writes over the other. Re-entrant per process.
with_conf_lock() {
  if [ -n "${PG_CONF_LOCKED:-}" ]; then "$@"; return; fi
  local rc
  mkdir -p "$CONF_DIR" 2>/dev/null
  {
    flock -w 30 8 || { echo "the path list is busy (another change is being saved) - try again" >&2; return 1; }
    PG_CONF_LOCKED=1; "$@"; rc=$?; PG_CONF_LOCKED=""
  } 8>"$CONF_DIR/.conf.lock"
  return "$rc"
}

# load_conf <file> - reads a conf file into the caller's scope after validating it. It is parsed, never
# executed: only the known keys are taken, as literal text, so nothing in a conf file (an imported one, or a
# path name with $ or `) can run a command as root. Returns 1 (and logs) on corruption.
load_conf() {
  local f="$1" line k v
  if [ ! -r "$f" ]; then log_error "config unreadable: $f"; return 1; fi
  # byte-wise (LC_ALL=C), so no character in a comment can depend on the locale; a single bad read (seen once
  # on a busy server, the file itself unchanged) is not a corrupted file, so look once more before saying so
  if LC_ALL=C grep -qvE '^([A-Z_]+=.*|#.*|[[:space:]]*)$' "$f" 2>/dev/null; then
    sleep 1
    if LC_ALL=C grep -qvE '^([A-Z_]+=.*|#.*|[[:space:]]*)$' "$f" 2>/dev/null; then
      log_error "config appears corrupted (unexpected content): $f"
      return 1
    fi
  fi
  TARGET_PATH=""; PATTERN="*"; RETENTION_VALUE=1; RETENTION_UNIT="days"
  ENABLED=0; LAST_PURGE=0; LAST_FREED=0; SCHEMA_VERSION=1; HOLD_SEC=""; PATH_ALLOW_TRUNCATE=""
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    [[ "$line" =~ ^([A-Z_]+)=(.*)$ ]] || continue
    k=${BASH_REMATCH[1]}; v=${BASH_REMATCH[2]}
    if [[ "$v" =~ ^\"(.*)\"$ ]] || [[ "$v" =~ ^\'(.*)\'$ ]]; then v=${BASH_REMATCH[1]}; fi
    case "$k" in
      TARGET_PATH|PATTERN|RETENTION_UNIT) printf -v "$k" '%s' "$v";;
      RETENTION_VALUE|ENABLED|HOLD_SEC|PATH_ALLOW_TRUNCATE) printf -v "$k" '%s' "$v";;   # checked below
      SCHEMA_VERSION|LAST_PURGE|LAST_FREED) [[ "$v" =~ ^[0-9]{1,18}$ ]] && printf -v "$k" '%s' "$(( 10#$v ))";;   # numbers only, decimal
    esac
  done < "$f"
  if [ -n "$HOLD_SEC" ] && ! [[ "$HOLD_SEC" =~ ^[0-9]{1,12}$ ]]; then
    log_error "config has an invalid HOLD_SEC ('$HOLD_SEC'), skipping: $f"; return 1
  fi
  # decimal: a "08" (hand-edited or imported) must not be read as octal later - that stops the script
  [ -n "$HOLD_SEC" ] && HOLD_SEC=$(( 10#$HOLD_SEC ))
  [[ "$RETENTION_VALUE" =~ ^[0-9]{1,9}$ ]] && RETENTION_VALUE=$(( 10#$RETENTION_VALUE ))
  if [ -n "$PATH_ALLOW_TRUNCATE" ] && ! [[ "$PATH_ALLOW_TRUNCATE" =~ ^[01]$ ]]; then
    log_error "config has an invalid PATH_ALLOW_TRUNCATE ('$PATH_ALLOW_TRUNCATE'), skipping: $f"; return 1
  fi
  if ! validate_conf_values "$TARGET_PATH" "$PATTERN" "$RETENTION_VALUE" "$RETENTION_UNIT" "$ENABLED" >/dev/null 2>&1; then
    log_error "config failed validation, skipping: $f"
    return 1
  fi
  return 0
}

# ============================================================
# SECTION: Storage Estimation
# ============================================================
# estimate <path> <pattern> <threshold_minutes>
# echoes:  total_bytes  freed_bytes  total_count  freed_count  oldest_epoch
estimate() {
  local path="$1" pattern="$2" thr_min="$3"
  local now thr_sec
  now=$(date +%s); thr_sec=$(( thr_min * 60 ))
  if [ ! -d "$path" ]; then echo "0 0 0 0 0"; return; fi
  find "$path" -type f -name "$pattern" -printf '%T@ %s\n' 2>/dev/null | \
    awk -v now="$now" -v thr="$thr_sec" '
    { mtime=$1; sz=$2; total+=sz; count++;
      age = now - mtime
      if (age > thr) { freed+=sz; fcount++ }
      if (oldest=="" || mtime<oldest) oldest=mtime }
    END { printf "%d %d %d %d %d\n", total+0, freed+0, count+0, fcount+0, oldest+0 }'
}

# Show an impact preview table for a path across the chosen + preset retentions
impact_preview() {
  local path="$1" pattern="$2" sel_val="$3" sel_unit="$4"
  echo
  echo "${C_BOLD}Storage impact for${C_RESET} ${C_CYAN}$path${C_RESET} ${C_DIM}(pattern: $pattern)${C_RESET}"
  if [ ! -d "$path" ]; then
    echo "${C_YELLOW}Path does not exist yet - no data to estimate.${C_RESET}"; return
  fi

  # baseline stats (threshold 0 = everything counts as total)
  read -r total _ count _ oldest <<<"$(estimate "$path" "$pattern" 0)"
  if [ "$count" -eq 0 ]; then
    echo "${C_YELLOW}No matching files found - nothing to estimate.${C_RESET}"; return
  fi

  local now span_days avg_day=0
  now=$(date +%s)
  span_days=$(( (now - oldest) / 86400 )); [ "$span_days" -lt 1 ] && span_days=1
  avg_day=$(( total / span_days ))

  printf "  %sCurrent matching data:%s %s across %s files (oldest ~%sd)\n" \
    "$C_DIM" "$C_RESET" "$(human "$total")" "$count" "$span_days"
  printf "  %sEst. average growth:%s   ~%s/day\n\n" "$C_DIM" "$C_RESET" "$(human "$avg_day")"

  printf "  %-22s %-12s %-12s %-14s\n" "Retention" "Frees now" "Keeps" "Est. steady use"
  printf "  %s\n" "----------------------------------------------------------------"

  local _rows=("Hourly (1 hour):1:hours" "Daily (1 day):1:days" "Weekly (7 days):7:days" "Monthly (30 days):30:days")
  local row label v u mins frees keeps steady days color
  for row in "${_rows[@]}"; do
    IFS=':' read -r label v u <<<"$row"
    mins=$(unit_to_min "$v" "$u")
    read -r t f _ _ _ <<<"$(estimate "$path" "$pattern" "$mins")"
    frees=$f; keeps=$(( t - f )); [ "$keeps" -lt 0 ] && keeps=0
    days=$(( mins / 1440 )); [ "$days" -lt 1 ] && days=1
    steady=$(( avg_day * days ))
    printf "  %-22s %-12s %-12s ~%-14s\n" "$label" "$(human "$frees")" "$(human "$keeps")" "$(human "$steady")"
  done

  echo
  mins=$(unit_to_min "$sel_val" "$sel_unit")
  read -r t f _ _ _ <<<"$(estimate "$path" "$pattern" "$mins")"
  frees=$f; keeps=$(( t - f )); [ "$keeps" -lt 0 ] && keeps=0
  days=$(( mins / 1440 )); [ "$days" -lt 1 ] && days=1
  steady=$(( avg_day * days ))
  printf "  ${C_GREEN}${C_BOLD}%-22s${C_RESET} %-12s %-12s ~%-14s\n" \
    "▶ Your choice: ${sel_val} ${sel_unit}" "$(human "$frees")" "$(human "$keeps")" "$(human "$steady")"
  echo
  echo "${C_DIM}\"Frees now\" = data older than the retention that would be purged on next run.${C_RESET}"
}

# ============================================================
# SECTION: Storage Overview
# ============================================================
usage_bar() {  # <percent>
  local pct=${1:-0} width=30 filled color
  filled=$(( pct * width / 100 )); [ "$filled" -gt "$width" ] && filled="$width"
  if   [ "$pct" -ge 90 ]; then color="$C_RED"
  elif [ "$pct" -ge 75 ]; then color="$C_YELLOW"
  else color="$C_GREEN"; fi
  printf "%s[" "$color"
  local i
  for ((i=0;i<width;i++)); do
    if [ "$i" -lt "$filled" ]; then printf "#"; else printf "${C_GREY}-${color}"; fi
  done
  printf "]%s %s%%%s" "$C_RESET" "$pct" "$C_RESET"
}

storage_overview() {
  local root_pct
  root_pct=$(df --output=pcent / 2>/dev/null | tail -1 | tr -dc '0-9')
  echo "${C_BOLD}Instance Storage${C_RESET}"
  printf "  root (/)  "; usage_bar "${root_pct:-0}"; echo
  echo
  printf "  %-26s %8s %8s %8s %6s\n" "Filesystem" "Size" "Used" "Avail" "Use%"
  hr "-"
  df -h --output=source,size,used,avail,pcent -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | tail -n +2 | while read -r src size used avail pct; do
      printf "  ${C_DIM}%-26s${C_RESET} %8s %8s %8s %6s\n" "$src" "$size" "$used" "$avail" "$pct"
    done
}

# ============================================================
# SECTION: Aggregate Statistics (used by dashboard, --stats)
# ============================================================
# Populates globals: STAT_TOTAL STAT_ENABLED STAT_DISABLED STAT_LAST_RUN
#                     STAT_TOTAL_FREED STAT_INVALID
collect_stats() {
  STAT_TOTAL=0; STAT_ENABLED=0; STAT_DISABLED=0; STAT_LAST_RUN=0
  STAT_TOTAL_FREED=0; STAT_INVALID=0
  local f en lp lf
  for f in $(list_confs); do
    STAT_TOTAL=$(( STAT_TOTAL + 1 ))
    if ! ( load_conf "$f" ) >/dev/null 2>&1; then STAT_INVALID=$(( STAT_INVALID + 1 )); continue; fi
    # read in this shell (not at the end of a pipe, whose subshell threw the counts away)
    en=""; lp=""; lf=""
    read -r en lp lf < <(load_conf "$f" >/dev/null 2>&1 && echo "$ENABLED ${LAST_PURGE:-0} ${LAST_FREED:-0}")
    [ "$en" = "1" ] && STAT_ENABLED=$(( STAT_ENABLED + 1 )) || STAT_DISABLED=$(( STAT_DISABLED + 1 ))
    [ "${lp:-0}" -gt "$STAT_LAST_RUN" ] && STAT_LAST_RUN=$lp
    STAT_TOTAL_FREED=$(( STAT_TOTAL_FREED + ${lf:-0} ))
  done
}

# ============================================================
# SECTION: Dashboard
# ============================================================
header() {
  clear 2>/dev/null
  local w title
  w=$(term_width); [ "$w" -gt 68 ] && w=68; [ "$w" -lt 40 ] && w=40
  echo "${C_MAGENTA}${C_BOLD}╔$(printf '%*s' $((w-2)) '' | tr ' ' '═')╗${C_RESET}"
  printf "${C_MAGENTA}${C_BOLD}║${C_RESET}  ${C_CYAN}${C_BOLD}%-$((w-6))s${C_RESET}${C_MAGENTA}${C_BOLD}║${C_RESET}\n" "${APP_NAME} v${APP_VERSION}"
  printf "${C_MAGENTA}${C_BOLD}║${C_RESET}  ${C_GREY}%-$((w-6))s${C_RESET}${C_MAGENTA}${C_BOLD}║${C_RESET}\n" "$(date '+%A %d %b %Y  %H:%M:%S')  •  $(hostname)"
  echo "${C_MAGENTA}${C_BOLD}╚$(printf '%*s' $((w-2)) '' | tr ' ' '═')╝${C_RESET}"
  echo
}

service_state() {
  if systemctl is-active --quiet "${SERVICE_NAME}.service" 2>/dev/null; then
    printf "%b service: %sACTIVE%s" "$(dot "$C_GREEN")" "$C_GREEN$C_BOLD" "$C_RESET"
    printf "  ${C_DIM}(realtime - purge pass every $(human_secs "$PG_PASS_SEC"))${C_RESET}"
  else
    printf "%b service: %sSTOPPED%s" "$(dot "$C_RED")" "$C_RED$C_BOLD" "$C_RESET"
  fi
  echo
}

# Returns 0 if config directory / marker / paths dir all look sane
config_health_ok() {
  [ -d "$CONF_DIR" ] && [ -d "$PATHS_DIR" ] && [ -f "$MARKER" ]
}

dashboard() {
  header
  storage_overview
  echo
  service_state
  collect_stats
  echo
  echo "${C_BOLD}Summary${C_RESET}"
  printf "  %-22s %s\n" "Configured paths:" "$STAT_TOTAL"
  printf "  %-22s %s%s${C_RESET} / %s%s${C_RESET}\n" "Enabled / disabled:" "$C_GREEN" "$STAT_ENABLED" "$C_YELLOW" "$STAT_DISABLED"
  printf "  %-22s %s\n" "Last run:" "$(rel_time "$STAT_LAST_RUN")"
  printf "  %-22s %s%s${C_RESET}\n" "Lifetime reclaimed:" "$C_GREEN" "$(human "$STAT_TOTAL_FREED")"
  if [ "$STAT_INVALID" -gt 0 ]; then
    warn_msg "${STAT_INVALID} config file(s) failed validation - see Health Check"
  fi
  echo
  echo "${C_BOLD}Configured Purge Paths${C_RESET}"
  if [ "$STAT_TOTAL" -eq 0 ]; then
    echo "  ${C_DIM}(none yet - choose 'Add a purge path' to begin)${C_RESET}"
    return
  fi
  printf "  ${C_DIM}%-3s %-2s %-32s %-12s %-10s %-10s${C_RESET}\n" \
    "#" "" "Path" "Retention" "Last run" "Last freed"
  hr "-"
  local i=0 f
  for f in $(list_confs); do
    i=$(( i + 1 ))
    if ! load_conf "$f" >/dev/null 2>&1; then
      printf "  %-3s %b %-32s\n" "$i" "$(dot "$C_YELLOW")" "${C_YELLOW}(invalid config: $(basename "$f"))${C_RESET}"
      continue
    fi
    (
      load_conf "$f" >/dev/null 2>&1
      local d ret short shown
      if [ "$ENABLED" = "1" ]; then d="$C_GREEN"; else d="$C_RED"; fi
      short=$(unit_short "$RETENTION_UNIT")
      ret="${RETENTION_VALUE}${short}"
      if [[ "$PATTERN" != *"*"* ]]; then shown="${TARGET_PATH}/${PATTERN}"; else shown="$TARGET_PATH"; fi
      [ "${#shown}" -gt 32 ] && shown="...${shown: -29}"
      local freed_disp
      if   [ "$LAST_FREED" -gt 0 ];  then freed_disp=$(human "$LAST_FREED")
      elif [ "$LAST_PURGE" -gt 0 ];  then freed_disp="empty"
      else                                freed_disp="-"; fi
      printf "  %-3s %b %-32s %-12s %-10s %-10s\n" \
        "$i" "$(dot "$d")" "$shown" "$ret" "$(rel_time "$LAST_PURGE")" "$freed_disp"
    )
  done
}

# Build an index -> conf-file map and echo the file for a given menu number
conf_by_index() {
  local want="$1" i=0 f
  [[ "$want" =~ ^[0-9]{1,9}$ ]] || return 1
  want=$(( 10#$want ))
  for f in $(list_confs); do
    i=$(( i + 1 ))
    if [ "$i" = "$want" ]; then echo "$f"; return 0; fi
  done
  return 1
}

# ============================================================
# SECTION: Duration Picker
# ============================================================
# Prompts for value + unit, shows impact preview, returns via globals
PICK_VALUE=""; PICK_UNIT=""
pick_duration() {  # pick_duration <path> <pattern>
  local path="$1" pattern="$2" choice value unit
  while true; do
    echo
    echo "${C_BOLD}Set retention (files older than this are purged):${C_RESET}"
    echo "  ${C_CYAN}1${C_RESET}) Hours"
    echo "  ${C_CYAN}2${C_RESET}) Days        ${C_DIM}(e.g. everyday = 1 day)${C_RESET}"
    echo "  ${C_CYAN}3${C_RESET}) Weeks"
    echo "  ${C_CYAN}4${C_RESET}) Months"
    echo "  ${C_CYAN}5${C_RESET}) Quick preset (daily / weekly / monthly)"
    echo "  ${C_CYAN}6${C_RESET}) Size (MB threshold - rotate when file exceeds X MB)"
    echo "  ${C_CYAN}7${C_RESET}) Schedule - every 24h elapsed  ${C_DIM}OR${C_RESET}  once a day at the daily time (${PG_DAILY_AT:0:2}:${PG_DAILY_AT:2:2}, setting PG_DAILY_AT)"
    echo "  ${C_CYAN}0${C_RESET}) Cancel"
    read -rp "Choose unit: " choice || menu_eof
    case "$choice" in
      1) unit="hours";;
      2) unit="days";;
      3) unit="weeks";;
      4) unit="months";;
      5)
        echo "  ${C_CYAN}1${C_RESET}) Daily (1 day)   ${C_CYAN}2${C_RESET}) Weekly (7 days)   ${C_CYAN}3${C_RESET}) Monthly (30 days)"
        read -rp "Preset: " p || menu_eof
        case "$p" in 1|a) value=1; unit=days;; 2|b) value=7; unit=days;; 3|c) value=30; unit=days;; *) continue;; esac
        ;;
      6) unit="mb";;
      7)
        echo
        echo "  ${C_CYAN}1${C_RESET}) Every 24 hours elapsed since last purge"
        echo "  ${C_CYAN}2${C_RESET}) Once per day at ${PG_DAILY_AT:0:2}:${PG_DAILY_AT:2:2} (setting PG_DAILY_AT)"
        read -rp "Choose: " sched || menu_eof
        case "$sched" in
          1|a) value=1; unit=days;;
          2|b) value=1; unit=midnight;;
          *) continue;;
        esac
        ;;
      0) return 1;;
      *) echo "${C_RED}Invalid choice.${C_RESET}"; continue;;
    esac
    if [ -z "${value:-}" ]; then
      if [ "$unit" = "mb" ]; then
        read -rp "Rotate when the file exceeds how many MB: " value || menu_eof
      else
        read -rp "Enter number of ${unit}: " value || menu_eof
      fi
      if ! is_positive_int "$value"; then
        echo "${C_RED}Please enter a whole number 1 or greater.${C_RESET}"; value=""; continue
      fi
      value=$(( 10#$value ))
    fi

    if [ "$unit" = "mb" ]; then
      echo
      echo "${C_BOLD}Size-based mode:${C_RESET} files exceeding ${C_CYAN}${value} MB${C_RESET} will be rotated on each run (old copy kept for the hold period, then deleted)."
      echo "${C_DIM}(mtime is not checked - applies regardless of file age)${C_RESET}"
    elif [ "$unit" = "midnight" ]; then
      echo
      echo "${C_BOLD}Midnight schedule:${C_RESET} file will be rotated once per day, ${C_CYAN}at ${PG_DAILY_AT:0:2}:${PG_DAILY_AT:2:2}${C_RESET} (setting PG_DAILY_AT)."
      echo "${C_DIM}(triggers on the first watcher check after midnight each day)${C_RESET}"
    else
      impact_preview "$path" "$pattern" "$value" "$unit"
    fi

    if confirm "Use retention of ${C_BOLD}${value} ${unit}${C_RESET}?"; then
      PICK_VALUE="$value"; PICK_UNIT="$unit"; return 0
    fi
    value=""; unit=""
  done
}

# ============================================================
# SECTION: Path Management Actions
# ============================================================

# find_conf_by_target_pattern <target> <pattern> - echoes matching conf path, if any
find_conf_by_target_pattern() {
  local target="$1" pattern="$2" f tp pp
  for f in $(list_confs 2>/dev/null); do
    tp=$(grep '^TARGET_PATH=' "$f" | head -1 | cut -d= -f2- | tr -d '"')
    pp=$(grep '^PATTERN='      "$f" | head -1 | cut -d= -f2- | tr -d '"')
    if [ "$tp" = "$target" ] && [ "$pp" = "$pattern" ]; then echo "$f"; return 0; fi
  done
  return 1
}

# replace_path_conf <target> <pattern> <value> <unit> <enabled> <last_purge> <last_freed> - writes the conf for
# target+pattern (HOLD_SEC / PATH_ALLOW_TRUNCATE from the caller) and drops any other conf for the same pair.
# Call under with_conf_lock.
replace_path_conf() {
  local id existing; id=$(path_id "$1/$2")
  existing=$(find_conf_by_target_pattern "$1" "$2") && [ "$existing" != "$PATHS_DIR/$id.conf" ] && rm -f "$existing"
  write_conf "$id" "$1" "$2" "$3" "$4" "$5" "$6" "$7"
}

# rewrite_path_conf <old conf file> <id> <target> <pattern> <value> <unit> <enabled> <last_purge> <last_freed>
# writes <id>.conf and removes the old file if it had another name (a conf whose name is not the id of its
# target+pattern would otherwise stay behind as a duplicate). Call under with_conf_lock.
rewrite_path_conf() {
  local old="$1" id="$2"; shift 2
  write_conf "$id" "$@" || return 1
  [ "$old" != "$PATHS_DIR/$id.conf" ] && rm -f "$old"
  return 0
}

# check_new_path <target-folder> <pattern> - sets NP_TARGET (canonical folder), or NP_ERR (why not) with rc 1.
# Call it directly, not inside $( ): the result is returned in those variables.
check_new_path() {
  NP_TARGET=""; NP_ERR=""
  NP_TARGET=$(safe_target "$1") || { NP_ERR=$NP_TARGET; NP_TARGET=""; return 1; }
  NP_ERR=$(safe_pattern "$2") || return 1
  NP_ERR=""; return 0
}

add_path() {
  header
  echo "${C_BOLD}Add a purge path${C_RESET}"
  echo
  echo "  Enter a ${C_CYAN}specific file${C_RESET} (e.g. /root/test.log) ${C_DIM}or${C_RESET} a ${C_CYAN}directory${C_RESET} (e.g. /var/log/myapp)"
  echo
  local target pattern
  read -rp "Path: " target
  target="${target%/}"
  local msg; if ! msg=$(is_safe_path "$target"); then echo "${C_RED}${msg}${C_RESET}"; pause; return; fi

  if [ -f "$target" ]; then
    # Existing file - split into dir + filename automatically
    pattern=$(basename "$target")
    target=$(dirname "$target")
    echo "${C_DIM}→ Specific file detected: managing '${target}/${pattern}'${C_RESET}"
  elif [ -d "$target" ]; then
    # Existing directory - ask for pattern
    read -rp "File pattern to match [${C_DIM}*${C_RESET}]: " pattern
    pattern="${pattern:-*}"
  else
    # Path doesn't exist yet - ask the user what it is
    echo "${C_YELLOW}That path doesn't exist yet. What are you configuring?${C_RESET}"
    echo "  ${C_CYAN}1${C_RESET}) A specific file path (e.g. /var/log/app.log)"
    echo "  ${C_CYAN}2${C_RESET}) A directory          (e.g. /var/log/myapp)"
    echo "  ${C_CYAN}0${C_RESET}) Cancel"
    read -rp "Choose: " type_choice || menu_eof
    case "$type_choice" in
      1)
        pattern=$(basename "$target")
        target=$(dirname "$target")
        echo "${C_DIM}→ Will manage '${target}/${pattern}' once it exists.${C_RESET}"
        ;;
      2)
        read -rp "File pattern to match [${C_DIM}*${C_RESET}]: " pattern
        pattern="${pattern:-*}"
        ;;
      0) return;;
      *) echo "${C_RED}Invalid choice.${C_RESET}"; pause; return;;
    esac
  fi
  # check the folder that will really be searched, not just what was typed
  if ! check_new_path "$target" "$pattern"; then echo "${C_RED}${NP_ERR}${C_RESET}"; pause; return; fi
  [ "$NP_TARGET" != "$target" ] && echo "${C_DIM}→ folder resolved to ${NP_TARGET}${C_RESET}"
  target=$NP_TARGET

  if ! pick_duration "$target" "$pattern"; then pause; return; fi
  HOLD_SEC=""; PATH_ALLOW_TRUNCATE=""
  path_options_prompt

  local id; id=$(path_id "${target}/${pattern}")
  local display_path initial_lp=0
  [ "$PICK_UNIT" = "midnight" ] && initial_lp=$(date +%s)
  if [[ "$pattern" != *"*"* ]]; then display_path="${target}/${pattern}"; else display_path="$target  (pattern: $pattern)"; fi
  # replaces any existing conf for the same target+pattern - prevents duplicates
  if with_conf_lock replace_path_conf "$target" "$pattern" "$PICK_VALUE" "$PICK_UNIT" 1 "$initial_lp" 0; then
    success_msg "Saved. '${display_path}' will keep the last ${PICK_VALUE} ${PICK_UNIT}."
    load_conf "$PATHS_DIR/$id.conf" >/dev/null 2>&1 && path_plan "$target" "$pattern"
    log_info "path added/updated: ${target}/${pattern} retention=${PICK_VALUE}${PICK_UNIT}"
  else
    error_msg "Failed to write config - check permissions on $PATHS_DIR."
    log_error "conf write failed for ${target}/${pattern}"
  fi
  pause
}

edit_path() {
  dashboard
  echo
  [ "$(count_confs)" -eq 0 ] && { echo "${C_DIM}No paths to edit.${C_RESET}"; pause; return; }
  read -rp "Edit which path number (0 to cancel): " n
  [ -z "$n" ] && return
  [ "$n" = "0" ] && return
  local f; f=$(conf_by_index "$n") || { echo "${C_RED}No such path.${C_RESET}"; pause; return; }
  load_conf "$f" || { echo "${C_RED}That config is corrupted - use Health Check to repair it.${C_RESET}"; pause; return; }
  local id; id=$(path_id "${TARGET_PATH}/${PATTERN}")
  local status_label; [ "$ENABLED" = "1" ] && status_label="${C_GREEN}enabled${C_RESET}" || status_label="${C_YELLOW}disabled${C_RESET}"
  echo
  echo "Editing ${C_CYAN}$TARGET_PATH${C_RESET}"
  echo "  ${C_DIM}pattern:${C_RESET} $PATTERN  ${C_DIM}retention:${C_RESET} ${RETENTION_VALUE} ${RETENTION_UNIT}  ${C_DIM}status:${C_RESET} ${status_label}"
  echo "  ${C_DIM}hold:${C_RESET} $( [ -n "${HOLD_SEC:-}" ] && human_secs "$HOLD_SEC" || echo "default ($(human_secs "$PG_GRACE_SEC"))")  ${C_DIM}empty in place:${C_RESET} $(case "${PATH_ALLOW_TRUNCATE:-}" in 1) echo on;; 0) echo off;; *) echo default;; esac)"
  echo "  ${C_CYAN}1${C_RESET}) Change retention duration"
  echo "  ${C_CYAN}2${C_RESET}) Change file pattern (current: $PATTERN)"
  echo "  ${C_CYAN}3${C_RESET}) Change hold time / empty-in-place for this path"
  echo "  ${C_CYAN}0${C_RESET}) Cancel"
  read -rp "Choose: " c
  case "$c" in
    1)
      if pick_duration "$TARGET_PATH" "$PATTERN"; then
        if with_conf_lock rewrite_path_conf "$f" "$id" "$TARGET_PATH" "$PATTERN" "$PICK_VALUE" "$PICK_UNIT" "$ENABLED" "$LAST_PURGE" "$LAST_FREED"; then
          success_msg "Updated."; log_info "retention changed for $TARGET_PATH -> ${PICK_VALUE}${PICK_UNIT}"
        else
          error_msg "Failed to write config - check permissions on $PATHS_DIR."
        fi
      fi;;
    2)
      read -rp "New pattern [*]: " np; np="${np:-*}"
      local pm; if ! pm=$(safe_pattern "$np"); then error_msg "$pm"; pause; return; fi
      local new_id; new_id=$(path_id "${TARGET_PATH}/${np}")
      if [ "$new_id" != "$id" ] && [ -f "$PATHS_DIR/$new_id.conf" ]; then
        error_msg "A config for '${TARGET_PATH}' with pattern '${np}' already exists - edit that entry instead."
        pause; return
      fi
      if with_conf_lock rewrite_path_conf "$f" "$new_id" "$TARGET_PATH" "$np" "$RETENTION_VALUE" "$RETENTION_UNIT" "$ENABLED" "$LAST_PURGE" "$LAST_FREED"; then
        success_msg "Pattern updated."; log_info "pattern changed for $TARGET_PATH -> $np"
      else
        error_msg "Failed to write config - check permissions on $PATHS_DIR."
      fi;;
    3)
      path_options_prompt
      if with_conf_lock rewrite_path_conf "$f" "$id" "$TARGET_PATH" "$PATTERN" "$RETENTION_VALUE" "$RETENTION_UNIT" "$ENABLED" "$LAST_PURGE" "$LAST_FREED"; then
        success_msg "Updated."; log_info "path options changed for $TARGET_PATH/$PATTERN: hold=${HOLD_SEC:-default} truncate=${PATH_ALLOW_TRUNCATE:-default}"
      else
        error_msg "Failed to write config - check permissions on $PATHS_DIR."
      fi;;
    *) :;;
  esac
  pause
}

toggle_path() {
  dashboard
  echo
  [ "$(count_confs)" -eq 0 ] && { echo "${C_DIM}No paths to toggle.${C_RESET}"; pause; return; }
  read -rp "Enable/disable which path number (0 to cancel): " n
  [ -z "$n" ] && return
  [ "$n" = "0" ] && return
  local f; f=$(conf_by_index "$n") || { echo "${C_RED}No such path.${C_RESET}"; pause; return; }
  load_conf "$f" || { echo "${C_RED}That config is corrupted - use Health Check to repair it.${C_RESET}"; pause; return; }
  local id new; id=$(path_id "${TARGET_PATH}/${PATTERN}")
  if [ "$ENABLED" = "1" ]; then new=0; else new=1; fi
  if with_conf_lock rewrite_path_conf "$f" "$id" "$TARGET_PATH" "$PATTERN" "$RETENTION_VALUE" "$RETENTION_UNIT" "$new" "$LAST_PURGE" "$LAST_FREED"; then
    [ "$new" = "1" ] && success_msg "Enabled purging for $TARGET_PATH" || warn_msg "Disabled purging for $TARGET_PATH"
    log_info "path $TARGET_PATH enabled=$new"
  else
    error_msg "Failed to write config - check permissions on $PATHS_DIR."
  fi
  pause
}

remove_path() {
  dashboard
  echo
  [ "$(count_confs)" -eq 0 ] && { echo "${C_DIM}No paths to remove.${C_RESET}"; pause; return; }
  read -rp "Remove which path number from management (0 to cancel): " n
  [ -z "$n" ] && return
  [ "$n" = "0" ] && return
  local f; f=$(conf_by_index "$n") || { echo "${C_RED}No such path.${C_RESET}"; pause; return; }
  load_conf "$f" || { echo "${C_RED}That config is corrupted.${C_RESET}"; confirm "Delete it anyway?" && rm -f "$f"; pause; return; }
  local _display
  if [[ "$PATTERN" != *"*"* ]]; then _display="${TARGET_PATH}/${PATTERN}"; else _display="$TARGET_PATH (pattern: $PATTERN)"; fi
  echo "${C_YELLOW}This only stops managing '${_display}'. No files are deleted now.${C_RESET}"
  if confirm "Remove from management?"; then
    with_conf_lock rm -f "$f"; success_msg "Removed."; log_info "path removed from management: ${TARGET_PATH}/${PATTERN}"
  fi
  pause
}

run_purge_now() {
  dashboard
  echo
  echo "${C_BOLD}Manual purge${C_RESET} - ${C_YELLOW}immediately${C_RESET} purges all enabled paths, ignoring schedule."
  echo "${C_DIM}Each file is rotated only when it is safe for its readers/writers; the old copy is kept for the hold period (default $(human_secs "$PG_GRACE_SEC")), then deleted. Unsafe files are skipped.${C_RESET}"
  if confirm "Force-purge all enabled paths right now?"; then
    echo
    PG_LOCK_WAIT=900 with_lock do_worker "verbose" "force"
    success_msg "Done."
  fi
  pause
}

service_control() {
  header
  echo "${C_BOLD}Purge service control${C_RESET}"
  echo
  service_state
  echo
  echo "  ${C_CYAN}1${C_RESET}) Enable + start  (realtime watcher, purge pass every $(human_secs "$PG_PASS_SEC"))"
  echo "  ${C_CYAN}2${C_RESET}) Stop + disable  (no automatic purging)"
  echo "  ${C_CYAN}3${C_RESET}) Show detailed service status"
  echo "  ${C_CYAN}4${C_RESET}) Restart service"
  echo "  ${C_CYAN}0${C_RESET}) Back"
  read -rp "Choose: " c
  case "$c" in
    1) service_start_guarded;;
    2) if systemctl disable --now "${SERVICE_NAME}.service" >/dev/null 2>&1; then
         warn_msg "Service stopped and disabled."; log_warn "service disabled"
       else
         error_msg "Failed to disable service."; log_error "failed to disable service"
       fi;;
    3) systemctl status "${SERVICE_NAME}.service" --no-pager 2>&1 | head -25;;
    4) if systemctl restart "${SERVICE_NAME}.service" >/dev/null 2>&1; then
         success_msg "Service restarted."; log_success "service restarted"
       else
         error_msg "Failed to restart service."; log_error "failed to restart service"
       fi;;
    *) return;;
  esac
  pause
}

view_log() {
  header
  echo "${C_BOLD}Recent purge activity${C_RESET}  ${C_DIM}($LOG_FILE)${C_RESET}"
  echo
  if [ -f "$LOG_FILE" ]; then tail -n 30 "$LOG_FILE"; else echo "${C_DIM}No log yet.${C_RESET}"; fi
  pause
}

# ============================================================
# SECTION: Health Check / Diagnostics
# ============================================================
health_check() {
  header
  echo "${C_BOLD}Health Check${C_RESET}"
  echo
  local ok=1 missing

  printf "  %-40s" "Configuration directory"
  if [ -d "$CONF_DIR" ]; then success_msg "$CONF_DIR"; else error_msg "missing"; ok=0; fi

  printf "  %-40s" "Paths directory"
  if [ -d "$PATHS_DIR" ]; then success_msg "$PATHS_DIR"; else error_msg "missing"; ok=0; fi

  printf "  %-40s" "First-run marker"
  if [ -f "$MARKER" ]; then success_msg "present"; else warn_msg "not installed yet"; fi

  printf "  %-40s" "Log file"
  if [ -w "$LOG_FILE" ] || touch "$LOG_FILE" 2>/dev/null; then success_msg "$LOG_FILE writable"; else error_msg "not writable"; ok=0; fi

  printf "  %-40s" "systemd service installed"
  if [ -f "$SERVICE_FILE" ]; then success_msg "yes"; else warn_msg "no"; fi

  printf "  %-40s" "systemd service active"
  if systemctl is-active --quiet "${SERVICE_NAME}.service" 2>/dev/null; then success_msg "active"; else warn_msg "inactive"; fi

  printf "  %-40s" "Required dependencies"
  if missing=$(check_dependencies); then success_msg "all present"; else error_msg "missing: $(echo "$missing" | tr '\n' ' ')"; ok=0; fi

  printf "  %-40s" "Installed binary matches this script"
  if [ -f "$SELF_INSTALL_PATH" ]; then
    if cmp -s "$0" "$SELF_INSTALL_PATH" 2>/dev/null; then success_msg "up to date"; else warn_msg "differs - consider re-running setup"; fi
  else
    warn_msg "not installed"
  fi

  echo
  echo "${C_BOLD}Path configuration validation${C_RESET}"
  local f total=0 bad=0
  for f in $(list_confs); do
    total=$(( total + 1 ))
    if ! load_conf "$f" >/dev/null 2>&1; then
      bad=$(( bad + 1 )); error_msg "corrupted: $(basename "$f")"
    fi
  done
  if [ "$total" -eq 0 ]; then
    echo "  ${C_DIM}no paths configured yet${C_RESET}"
  elif [ "$bad" -eq 0 ]; then
    success_msg "all ${total} path configs valid"
  else
    warn_msg "${bad}/${total} path configs failed validation"
    ok=0
  fi

  echo
  if [ "$ok" -eq 1 ]; then
    success_msg "Overall status: HEALTHY"
  else
    error_msg "Overall status: ISSUES FOUND - see 'Repair configuration' in the menu"
  fi
  pause
}

# repair_configuration - quarantines corrupted conf files, recreates missing dirs
repair_configuration() {
  header
  echo "${C_BOLD}Repair configuration${C_RESET}"
  echo
  mkdir -p "$PATHS_DIR" "$BACKUP_DIR" 2>/dev/null
  chmod 700 "$CONF_DIR" "$PATHS_DIR" 2>/dev/null
  touch "$LOG_FILE" 2>/dev/null; chmod 640 "$LOG_FILE" 2>/dev/null

  local quarantine="${CONF_DIR}/quarantine"
  local f moved=0
  for f in $(list_confs); do
    if ! load_conf "$f" >/dev/null 2>&1; then
      mkdir -p "$quarantine" 2>/dev/null
      mv -f "$f" "$quarantine/$(basename "$f").$(date +%s)" 2>/dev/null && moved=$(( moved + 1 ))
    fi
  done

  if [ "$moved" -gt 0 ]; then
    warn_msg "Quarantined ${moved} corrupted config(s) to ${quarantine}"
    log_warn "repair: quarantined ${moved} corrupted config file(s)"
  else
    success_msg "No corrupted configs found."
  fi

  echo
  echo "  ${C_CYAN}1${C_RESET}) Repair file permissions on config directory"
  echo "  ${C_CYAN}0${C_RESET}) Done"
  read -rp "Choose: " c
  if [ "$c" = "1" ]; then
    chmod 700 "$CONF_DIR" "$PATHS_DIR" 2>/dev/null
    chmod 600 "$PATHS_DIR"/*.conf 2>/dev/null
    chmod 640 "$LOG_FILE" 2>/dev/null
    success_msg "Permissions reset to safe defaults."
    log_info "repair: permissions reset"
  fi
  pause
}

# ============================================================
# SECTION: Backup / Restore / Export / Import
# ============================================================
backup_configuration() {  # backup_configuration [dest_file]
  local dest="${1:-}"
  mkdir -p "$BACKUP_DIR" 2>/dev/null
  [ -z "$dest" ] && dest="${BACKUP_DIR}/purging-config-$(date +%Y%m%d-%H%M%S).tar.gz"
  if [ ! -d "$CONF_DIR" ]; then echo "error: nothing to back up - $CONF_DIR does not exist" >&2; return 1; fi
  # only the configuration: not earlier backups (each backup would contain all the previous ones and double
  # in size), not lock or temp files, not broken configs set aside by Health Check (quarantine/)
  local b; b=$(basename "$CONF_DIR")
  if tar -czf "$dest" -C "$(dirname "$CONF_DIR")" --exclude="$b/backups" --exclude="$b/quarantine" --exclude="$b/.*.lock" --exclude="$b/*.tmp.*" \
       --exclude="$b/paths.d/.*" "$b" 2>/dev/null; then
    chmod 600 "$dest" 2>/dev/null
    echo "Backup written to: $dest"
    log_success "configuration backed up to $dest"
    return 0
  else
    echo "error: backup failed" >&2
    log_error "backup failed"
    return 1
  fi
}

restore_configuration() {  # restore_configuration <archive>
  local src="$1" b tmp bad f n=0 skipped=0
  [ -f "$src" ] || { echo "error: backup file not found: $src" >&2; return 1; }
  if ! tar -tzf "$src" >/dev/null 2>&1; then
    echo "error: '$src' is not a valid tar.gz archive" >&2
    return 1
  fi
  # Only a backup made by this tool is accepted: nothing in it may land outside the config folder. It is
  # unpacked into a temporary folder first and every path config is checked before anything is replaced.
  b=$(basename "$CONF_DIR")
  bad=$(tar -tzf "$src" 2>/dev/null | grep -vE "^(\./)?${b}/?\$|^(\./)?${b}/(engine\.conf|\.installed|\.[a-z]+\.lock|paths\.d/?|paths\.d/[0-9A-Za-z_.-]+\.conf|backups(/.*)?|quarantine(/.*)?)\$" | head -1)
  [ -z "$bad" ] || { echo "error: '$src' is not a backup of this tool (unexpected entry: $bad) - nothing restored" >&2; return 1; }
  tmp=$(mktemp -d) || { echo "error: cannot create a temporary folder" >&2; return 1; }
  # (backups made before v2.6.11 may hold quarantine/ - accepted above, never unpacked)
  if ! tar -xzf "$src" -C "$tmp" --no-same-owner --exclude="$b/backups" --exclude="$b/quarantine" 2>/dev/null \
     || [ -n "$(find "$tmp" ! -type f ! -type d 2>/dev/null | head -1)" ]; then
    rm -rf "$tmp"; echo "error: '$src' could not be unpacked safely - nothing restored" >&2; return 1
  fi
  local safety; safety="${BACKUP_DIR}/pre-restore-$(date +%Y%m%d-%H%M%S).tar.gz"
  # the current paths are deleted below: never without a safety copy of them
  if [ -d "$CONF_DIR" ] && ! backup_configuration "$safety" >/dev/null 2>&1; then
    rm -rf "$tmp"; rm -f "$safety"
    echo "error: could not save a safety backup of the current configuration (disk full?) - nothing restored" >&2; return 1
  fi
  _restore_apply() {
    local c
    for c in "$PATHS_DIR"/*.conf; do [ -e "$c" ] && rm -f "$c"; done    # paths added after the backup go too
    for f in "$tmp/$b/paths.d"/*.conf; do
      [ -e "$f" ] || continue
      if load_conf "$f" 2>/dev/null && check_new_path "$TARGET_PATH" "$PATTERN"; then
        replace_path_conf "$NP_TARGET" "$PATTERN" "$RETENTION_VALUE" "$RETENTION_UNIT" "$ENABLED" "$LAST_PURGE" "$LAST_FREED" && n=$(( n + 1 ))
      else
        skipped=$(( skipped + 1 )); echo "skipped ${f##*/}: ${NP_ERR:-invalid config}" >&2
      fi
    done
    if [ -f "$tmp/$b/engine.conf" ]; then
      install -m 600 "$tmp/$b/engine.conf" "$SETTINGS_FILE.tmp.$$" && mv -f "$SETTINGS_FILE.tmp.$$" "$SETTINGS_FILE"
    else
      rm -f "$SETTINGS_FILE"                                           # the backup had only default settings
    fi
  }
  if ! with_conf_lock _restore_apply; then
    rm -rf "$tmp"; settings_load
    echo "error: the restore did not complete - the current configuration was saved first to: $safety" >&2
    log_error "restore from $src did not complete (safety backup: $safety)"
    return 1
  fi
  rm -rf "$tmp"
  settings_load
  echo "Restored configuration from: $src  (${n} path(s)$([ "$skipped" -gt 0 ] && echo ", ${skipped} skipped"))"
  echo "(pre-restore safety backup saved to: $safety)"
  log_success "configuration restored from $src (${n} paths, ${skipped} skipped)"
  return 0
}

export_configuration() {  # export_configuration <dest_file>
  local dest="$1" f
  {
    echo "# Purging Management Console - exported configuration"
    echo "# schema_version=${CONFIG_SCHEMA_VERSION} exported=$(date -Iseconds 2>/dev/null || date)"
    for f in $(list_confs); do
      echo "## $(basename "$f")"
      cat "$f"
    done
  } > "$dest" 2>/dev/null && { echo "Exported to: $dest"; log_info "configuration exported to $dest"; return 0; }
  echo "error: export failed" >&2; return 1
}

import_configuration() {  # import_configuration <src_file>
  local src="$1"
  [ -f "$src" ] || { echo "error: file not found: $src" >&2; return 1; }
  mkdir -p "$PATHS_DIR" 2>/dev/null
  # Each "## <name>.conf" section is collected in a temporary folder, then checked like a newly added path and
  # written by this tool under its proper name. The section name is never used as a file name, so an import
  # cannot write outside the config folder; the content is parsed, never executed.
  local tmp line cur="" sec=0 imported=0 skipped=0 f
  tmp=$(mktemp -d) || { echo "error: cannot create a temporary folder" >&2; return 1; }
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    if [[ "$line" == "## "*.conf ]]; then
      sec=$(( sec + 1 )); cur="$tmp/$sec.conf"; : > "$cur"
    elif [ -n "$cur" ] && [[ "$line" != "#"* ]]; then
      printf '%s\n' "$line" >> "$cur"
    fi
  done < "$src"
  for (( f=1; f<=sec; f++ )); do
    if load_conf "$tmp/$f.conf" 2>/dev/null && check_new_path "$TARGET_PATH" "$PATTERN"; then
      if with_conf_lock replace_path_conf "$NP_TARGET" "$PATTERN" "$RETENTION_VALUE" "$RETENTION_UNIT" "$ENABLED" "$LAST_PURGE" "$LAST_FREED"; then
        imported=$(( imported + 1 ))
      else skipped=$(( skipped + 1 )); fi
    else
      skipped=$(( skipped + 1 )); echo "skipped section $f: ${NP_ERR:-invalid or unsafe config}" >&2
    fi
  done
  rm -rf "$tmp"
  echo "Imported ${imported} path config(s) from: $src$([ "$skipped" -gt 0 ] && echo "  (${skipped} skipped)")"
  log_info "configuration imported from $src (${imported} paths, ${skipped} skipped)"
  [ "$skipped" -eq 0 ]
}

# ============================================================
# SECTION: Statistics Screen
# ============================================================
show_stats() {
  header
  echo "${C_BOLD}Statistics${C_RESET}"
  echo
  collect_stats
  printf "  %-28s %s\n" "Total configured paths:" "$STAT_TOTAL"
  printf "  %-28s %s\n" "Enabled:" "${C_GREEN}${STAT_ENABLED}${C_RESET}"
  printf "  %-28s %s\n" "Disabled:" "${C_YELLOW}${STAT_DISABLED}${C_RESET}"
  printf "  %-28s %s\n" "Invalid configs:" "${STAT_INVALID}"
  printf "  %-28s %s\n" "Last run (any path):" "$(rel_time "$STAT_LAST_RUN")"
  printf "  %-28s %s\n" "Lifetime storage reclaimed:" "$(human "$STAT_TOTAL_FREED")"
  echo
  if [ -f "$LOG_FILE" ]; then
    echo "${C_BOLD}Recent activity (last 10)${C_RESET}"
    grep -E 'SUCCESS|cleared' "$LOG_FILE" 2>/dev/null | tail -10
  fi
  pause
}

# ============================================================
# SECTION: System Information / Diagnostics
# ============================================================
show_system_info() {
  header
  echo "${C_BOLD}System Information${C_RESET}"
  echo
  printf "  %-20s %s\n" "Hostname:"       "$(hostname)"
  printf "  %-20s %s\n" "Kernel:"         "$(uname -sr)"
  printf "  %-20s %s\n" "Uptime:"         "$(uptime -p 2>/dev/null || uptime)"
  printf "  %-20s %s\n" "Script version:" "$APP_VERSION"
  printf "  %-20s %s\n" "Schema version:"  "$CONFIG_SCHEMA_VERSION"
  printf "  %-20s %s\n" "Config dir:"     "$CONF_DIR"
  printf "  %-20s %s\n" "Log file:"       "$LOG_FILE"
  printf "  %-20s %s\n" "Installed at:"   "${SELF_INSTALL_PATH} $( [ -f "$SELF_INSTALL_PATH" ] && echo "(present)" || echo "(not installed)")"
  pause
}

# ============================================================
# SECTION: Installer
# ============================================================
install_units() {
  # Stop and remove old timer if present (superseded by the watcher service)
  systemctl disable --now "${SERVICE_NAME}.timer" >/dev/null 2>&1
  rm -f "$TIMER_FILE"

  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=${APP_NAME} realtime watcher
After=network.target

[Service]
Type=simple
ExecStart=${SELF_INSTALL_PATH} --watch
Restart=always
RestartSec=5
# a stop goes to the watcher only: it finishes the file in hand (never stops between a move and the reload)
KillMode=mixed
TimeoutStopSec=120

[Install]
WantedBy=multi-user.target
EOF
  if [ $? -ne 0 ]; then
    error_msg "Failed to write $SERVICE_FILE."
    return 1
  fi
  systemctl daemon-reload
}

install_self() {
  local src; src=$(readlink -f "$0")
  mkdir -p "$(dirname "$SELF_INSTALL_PATH")"
  if [ "$src" != "$SELF_INSTALL_PATH" ]; then
    # write a new file and rename it over the old one: a running copy (the service) keeps reading its
    # own, unchanged file instead of having it rewritten underneath it
    local tmp="${SELF_INSTALL_PATH}.new.$$"
    if ! cp "$src" "$tmp" || ! chmod 755 "$tmp" || ! bash -n "$tmp" || ! mv -f "$tmp" "$SELF_INSTALL_PATH"; then
      rm -f "$tmp"; error_msg "Failed to install script to $SELF_INSTALL_PATH."
      return 1
    fi
  fi
  chmod 755 "$SELF_INSTALL_PATH"
}

first_time_setup() {
  header
  echo "${C_BOLD}Welcome - first-time setup${C_RESET}"
  echo
  local missing
  if ! missing=$(check_dependencies); then
    error_msg "Missing required dependencies: $(echo "$missing" | tr '\n' ' ')"
    echo "Install them via your distribution's package manager before continuing."
    pause; return 1
  fi
  echo "This will:"
  echo "  ${C_GREEN}•${C_RESET} create config directory  ${C_DIM}$CONF_DIR${C_RESET}"
  echo "  ${C_GREEN}•${C_RESET} install this tool to      ${C_DIM}$SELF_INSTALL_PATH${C_RESET}"
  echo "  ${C_GREEN}•${C_RESET} install a systemd service (${SERVICE_NAME}) - not started until you say so"
  echo
  confirm "Proceed with setup?" || { echo "Setup cancelled."; return 1; }

  mkdir -p "$PATHS_DIR" "$BACKUP_DIR"; chmod 700 "$CONF_DIR" "$PATHS_DIR"
  touch "$LOG_FILE" 2>/dev/null; chmod 640 "$LOG_FILE" 2>/dev/null
  install_self   || { error_msg "Setup aborted."; return 1; }
  install_units  || { error_msg "Setup aborted."; return 1; }
  date +%s > "$MARKER"
  log_success "first-time setup completed"

  echo
  success_msg "Core setup complete."
  echo
  echo "${C_BOLD}The purge service is installed but NOT running.${C_RESET} Nothing is rotated or deleted yet."
  echo "  1. add your log paths (menu 2) - each one shows its plan"
  echo "  2. check the plans (menu 8)"
  echo "  3. start the service when you are happy: menu 11 → 1 (you will be asked to type start)"
  echo
  if confirm "Add your first purge path now?"; then add_path; fi
}

# ============================================================
# SECTION: Consumer Detection (read-only - never modifies anything)
# ============================================================
# Answers, per log file: who WRITES it (and in append mode or not), who
# READS it (rsyslog imfile / Fluentd tail / Wazuh logcollector / anything
# else holding it open), how far behind each reader is, and whether
# logrotate or Wazuh already manage it.

# (config locations come from the settings: DET_RSYSLOG_FILES, DET_LOGROTATE_FILES, DET_WAZUH_CONF, ...)

# det_glob_match <file> <pattern> - bash glob match, returns 0 on match
# Real path-glob semantics: * and ? stop at '/', ** crosses it (matches fluentd/rsyslog/wazuh/logrotate).
# "**/" also matches no folder at all (/var/log/**/*.log matches /var/log/app.log, as in fluentd and logrotate),
# and {a,b} is either alternative.
det_glob_match() {
  local f="$1" g="$2" re="" i c n=${#2} br=0
  [ -n "$g" ] || return 1
  for (( i=0; i<n; i++ )); do
    c="${g:i:1}"
    case "$c" in
      '*') if [ "${g:i+1:1}" = '*' ]; then
             if [ "${g:i+2:1}" = '/' ]; then re+='(.*/)?'; i=$(( i + 2 )); else re+='.*'; i=$(( i + 1 )); fi
           else re+='[^/]*'; fi;;
      '?') re+='[^/]';;
      '['|']') re+="$c";;
      '{') br=$(( br + 1 )); re+='(';;
      '}') if [ "$br" -gt 0 ]; then br=$(( br - 1 )); re+=')'; else re+='\}'; fi;;
      ',') if [ "$br" -gt 0 ]; then re+='|'; else re+=','; fi;;
      [.+\(\)^$\|]) re+="\\$c";;
      *) re+="$c";;
    esac
  done
  [ "$br" -eq 0 ] || return 1                       # unbalanced braces: not a pattern we can read
  [[ "$f" =~ ^${re}$ ]]
}

# det_proc_users <file> - one line per process holding the file open:
#   pid|comm|kind|rw|append|pos     rw: r|w|rw   append: 1|0   kind: rsyslog|fluentd|wazuh|other
det_proc_users() {
  local real fd pid n flags pos comm cmd acc app kind rw
  real=$(readlink -f "$1" 2>/dev/null) || return 0
  while IFS= read -r fd; do
    pid=${fd#/proc/}; pid=${pid%%/*}; n=${fd##*/}
    flags=$(awk '/^flags:/{print $2}' "/proc/$pid/fdinfo/$n" 2>/dev/null)
    [ -n "$flags" ] || continue
    pos=$(awk '/^pos:/{print $2}' "/proc/$pid/fdinfo/$n" 2>/dev/null)
    acc=$(( 8#$flags & 3 )); app=$(( (8#$flags & 8#2000) != 0 ? 1 : 0 ))
    case "$acc" in 0) rw=r;; 1) rw=w;; *) rw=rw;; esac
    comm=$( { cat "/proc/$pid/comm"; } 2>/dev/null)
    cmd=$( { tr '\0' ' ' < "/proc/$pid/cmdline"; } 2>/dev/null)
    case "$comm $cmd" in
      *rsyslogd*)                          kind=rsyslog;;
      *fluentd*|*td-agent*|*fluent-bit*)   kind=fluentd;;
      *wazuh-logcollec*)                   kind=wazuh;;
      *)                                   kind=other;;
    esac
    [ "$comm" = java ] && [[ "$cmd" == *logstash* ]] && comm=logstash      # Logstash runs as "java"
    echo "$pid|$comm|$kind|$rw|$app|${pos:-0}"
  # Always by inode, never by the path text the kernel shows for the fd: a writer in a container or behind a
  # bind mount sees the file under another path (/logs/app.log for the host's /opt/app/logs/app.log). A name
  # match missed it, and the file was rotated under a writer that kept writing into the moved copy.
  # (DET_BY_INODE, still set by some callers, is now always the case.)
  # Not with find -samefile: find opens that file itself, so it showed up as a reader of every file it was
  # asked about. Each fd's device:inode is listed instead and compared here.
  done < <(id=$(stat -L -c '%d:%i' -- "$real" 2>/dev/null) && \
           find -L /proc/[0-9]*/fd -mindepth 1 -maxdepth 1 -printf '%D:%i\t%p\n' 2>/dev/null | awk -F'\t' -v id="$id" '$1 == id {print $2}')
}

# det_strip_comments <c|xml> - config text on stdin without its block comments, so a disabled input or output
# is not taken for a live one:  c = rsyslog /* ... */ (outside quotes; $Directive lines are left alone - their
# paths contain /* as in $IncludeConfig /etc/rsyslog.d/*.conf),  xml = Wazuh <!-- ... -->. Comments may span lines.
det_strip_comments() {
  awk -v mode="$1" '
    {
      line = $0; out = ""; q = ""
      if (!inc && mode == "c" && line ~ /^[ \t]*\$/) { print line; next }
      while (length(line) > 0) {
        if (inc) {
          e = index(line, endm)
          if (e == 0) { line = ""; break }
          line = substr(line, e + length(endm)); inc = 0; continue
        }
        if (mode == "xml") {
          s = index(line, "<!--")
          if (s == 0) { out = out line; break }
          out = out substr(line, 1, s - 1); line = substr(line, s + 4); inc = 1; endm = "-->"; continue
        }
        c = substr(line, 1, 1)
        if (q != "") {
          if (c == "\\") { out = out substr(line, 1, 2); line = substr(line, 3); continue }
          out = out c; if (c == q) q = ""; line = substr(line, 2); continue
        }
        if (c == "\"" || c == "\047") { q = c; out = out c; line = substr(line, 2); continue }
        if (substr(line, 1, 2) == "/*") { inc = 1; endm = "*/"; line = substr(line, 3); continue }
        out = out c; line = substr(line, 2)
      }
      print out
    }'
}

# det_expand_dates <pattern> - a reader path with date codes (fluentd %Y-%m-%d, Wazuh %Y/%b/%d) names only
# the current file, not every day's: today's and yesterday's names (yesterday's may still be read to its end).
# A pattern without date codes is printed as it is.
det_expand_dates() {
  if [[ "$1" == *%[A-Za-z]* ]]; then
    { LC_ALL=C date +"$1"; LC_ALL=C date -d '1 day ago' +"$1"; } 2>/dev/null | awk '!seen[$0]++'
  else
    printf '%s\n' "$1"
  fi
}

# det_rsyslog_inputs - "pattern|on|off" per imfile input (on = reopenOnTruncate="on").
# Inside a purge pass this comes from the 60 s cache (det_cache_refresh): it is asked for every file.
det_rsyslog_inputs() {
  if [ -n "${DET_FL_AT:-}" ]; then [ -n "$DET_RS_IN" ] && printf '%s\n' "$DET_RS_IN"; return 0; fi
  det_rsyslog_inputs_raw
}
det_rsyslog_inputs_raw() {
  local f blk pat re rsf
  mapfile -t rsf < <(list_glob DET_RSYSLOG_FILES)
  for f in ${rsf[@]+"${rsf[@]}"}; do [ -r "$f" ] && grep -vE '^[[:space:]]*#' "$f"; done 2>/dev/null | det_strip_comments c | tr '\n' ' ' \
    | grep -oiE 'input[[:space:]]*\([^)]*type[[:space:]]*=[[:space:]]*"imfile"[^)]*\)' | while IFS= read -r blk; do
        # the File= parameter itself - not stateFile= or any other name ending in "file"; spaces around = allowed
        pat=$(sed -nE 's/.*(^|[^A-Za-z])[Ff][Ii][Ll][Ee][[:space:]]*=[[:space:]]*"([^"]+)".*/\2/p' <<<"$blk")
        if grep -qiE 'reopenOnTruncate[[:space:]]*=[[:space:]]*"on"' <<<"$blk"; then re=on; else re=off; fi
        [ -n "$pat" ] && echo "$pat|$re"
      done
  for f in ${rsf[@]+"${rsf[@]}"}; do
    [ -r "$f" ] && grep -E '^\$InputFileName[[:space:]]' "$f" | awk '{print $2 "|off"}'
  done 2>/dev/null
  return 0
}

# det_rsyslog_patterns - imfile file patterns, one per line
det_rsyslog_patterns() { local p r; while IFS='|' read -r p r; do [ -n "$p" ] && printf '%s\n' "$p"; done < <(det_rsyslog_inputs); return 0; }

# det_rsyslog_outputs_raw - the files rsyslog WRITES, one per line (a glob where the name comes from a template):
#   action(type="omfile" file="/var/log/x.log" ...)          -> /var/log/x.log
#   action(type="omfile" dynaFile="T" ...) + template T       -> its string, each %property% as *
#   legacy lines:  *.info  -/var/log/messages   |   :programname, isequal, "x"  /var/log/x.log   |   *.* ?T
# rsyslog closes every one of these files on a HUP and opens it again only at its next write, so between
# bursts (a disk queue writes every minute or two) no process holds them. This list says who writes them then.
det_rsyslog_outputs_raw() {
  local f all blk t s line
  local -a rsf=()
  declare -A tpl=()
  mapfile -t rsf < <(list_glob DET_RSYSLOG_FILES)
  all=$(for f in ${rsf[@]+"${rsf[@]}"}; do [ -r "$f" ] && grep -vE '^[[:space:]]*#' "$f"; done 2>/dev/null | det_strip_comments c)
  [ -n "$all" ] || return 0
  # templates: template(name="T" type="string" string="...")  and  $template T,"..."
  while IFS= read -r blk; do
    t=$(sed -nE 's/.*(^|[^A-Za-z.])[Nn][Aa][Mm][Ee][[:space:]]*=[[:space:]]*"([^"]+)".*/\2/p' <<<"$blk")
    s=$(sed -nE 's/.*(^|[^A-Za-z.])[Ss][Tt][Rr][Ii][Nn][Gg][[:space:]]*=[[:space:]]*"([^"]+)".*/\2/p' <<<"$blk")
    [ -n "$t" ] && [ -n "$s" ] && tpl[$t]=$s
  done < <(tr '\n' ' ' <<<"$all" | grep -oiE 'template[[:space:]]*\([^)]*\)')
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*\$template[[:space:]]+([^,[:space:]]+)[[:space:]]*,[[:space:]]*\"([^\"]+)\" ]] && tpl[${BASH_REMATCH[1]}]=${BASH_REMATCH[2]}
  done <<<"$all"
  # omfile actions (spread over several lines)
  while IFS= read -r blk; do
    # the file= parameter itself - not fileOwner=, queue.filename= or any other name containing "file"
    s=$(sed -nE 's/.*(^|[^A-Za-z.])[Ff][Ii][Ll][Ee][[:space:]]*=[[:space:]]*"([^"]+)".*/\2/p' <<<"$blk")
    if [ -z "$s" ]; then
      t=$(sed -nE 's/.*(^|[^A-Za-z.])[Dd][Yy][Nn][Aa][Ff][Ii][Ll][Ee][[:space:]]*=[[:space:]]*"([^"]+)".*/\2/p' <<<"$blk")
      [ -n "$t" ] && s=${tpl[$t]:-}
      det_rs_dated_tpl "$s" && continue
    fi
    [[ "$s" == /* ]] && sed -E 's/%[^%]*%/*/g' <<<"$s"
  done < <(tr '\n' ' ' <<<"$all" | grep -oiE 'action[[:space:]]*\([^)]*type[[:space:]]*=[[:space:]]*"omfile"[^)]*\)')
  # legacy selector / filter lines: the last word is the file (-/path, /path) or a dynamic-file template (?T).
  # Directives ($WorkDirectory /var/spool/rsyslog) and anything with ( ... ) are not output lines.
  while IFS= read -r s; do
    case "$s" in
      /*) printf '%s\n' "$s";;
      \?*) t=${s#\?}; [[ "${tpl[$t]:-}" == /* ]] && ! det_rs_dated_tpl "${tpl[$t]}" && sed -E 's/%[^%]*%/*/g' <<<"${tpl[$t]}";;
    esac
  done < <(awk '$0 !~ /^[ \t]*\$/ && $0 !~ /[()]/ && NF >= 2 { w=$NF; sub(/;.*/, "", w); sub(/^-\//, "/", w); if (w ~ /^\// || w ~ /^\?[A-Za-z0-9_.-]+$/) print w }' <<<"$all")
  return 0
}

# det_rs_dated_tpl <template string> - 0 if the file name comes partly from the date (%$year%, %$day%,
# %timegenerated:...%, %$now% ...). Such a template names a new file (or folder: /remote/%$year%/%$month%/%$day%/
# syslog.log) every day; as a wildcard it would also claim every older day's file as written by rsyslog, so
# each old file was rotated (one rsyslog reload per file) instead of being left to expire. Not counted.
det_rs_dated_tpl() {
  local s="${1,,}"
  [[ "$s" =~ %[^%]*(year|month|day|hour|minute|qhour|hhour|now|timegenerated|timereported|date)[^%]*% ]]
}

# det_rsyslog_running - "1" if an rsyslogd process is running
det_rsyslog_running() {
  if command -v pgrep >/dev/null 2>&1; then pgrep -x rsyslogd >/dev/null 2>&1 && echo 1 || echo 0; return 0; fi
  local c n; for c in /proc/[0-9]*/comm; do read -r n < "$c" 2>/dev/null && [ "$n" = rsyslogd ] && { echo 1; return 0; }; done; echo 0
}

# det_rsyslog_writes <file> - 0 if a running rsyslog writes this file according to its config.
# A template name (glob) does not count for a date-named file: /var/log/fw-%$day%.log names today's file AND
# every older day's, and only today's is still written.
# Sets DET_RS_HOW: exact (the config names this very path) or glob (a template / wildcard matches it).
det_rsyslog_writes() {
  local f="$1" p outs run
  DET_RS_HOW=""
  if [ -n "${DET_FL_AT:-}" ]; then outs=$DET_RS_OUT; run=$DET_RS_RUN; else outs=$(det_rsyslog_outputs_raw); run=$(det_rsyslog_running); fi
  [ "$run" = 1 ] && [ -n "$outs" ] || return 1
  grep -qxF -- "$f" <<<"$outs" && { DET_RS_HOW=exact; return 0; }
  while IFS= read -r p; do
    [[ "$p" == *[*?]* ]] || continue
    pg_dated_name "${f##*/}" && continue
    det_glob_match "$f" "$p" && { DET_RS_HOW=glob; return 0; }
  done <<<"$outs"
  return 1
}

# det_fluentd_expand <conf> [depth] - the file plus everything it pulls in with @include (globs, relative paths)
det_fluentd_expand() {
  local c="$1" d="${2:-0}" inc base m
  [ -r "$c" ] || return 0
  echo "$c"
  [ "$d" -lt 4 ] || return 0
  base=$(dirname "$c")
  while IFS= read -r inc; do
    case "$inc" in http*|"") continue;; /*) ;; *) inc="$base/$inc";; esac
    for m in $inc; do [ -f "$m" ] && det_fluentd_expand "$m" $(( d + 1 )); done
  done < <(awk '/^[ \t]*@include[ \t]+/ {print $2}' "$c" 2>/dev/null)
}

# det_fluentd_confs - config files in use: every running fluentd / td-agent / fluent-package process
# (-c / --config, or FLUENT_CONF in its environment), the package defaults, and their @include files.
# Backup / disabled copies (*.bak, *.new, *.orig, *-old.conf, *.disabled) are ignored unless a running
# process was started with one.
det_fluentd_confs() {
  local p a prev c
  local -a argv
  {
    for p in /proc/[0-9]*; do
      # read the command line with builtins: one fork per process here cost hundreds of forks per scan.
      # (read -d '' rather than mapfile -d, which needs bash 4.4)
      argv=(); a=""
      while IFS= read -r -d '' a || [ -n "$a" ]; do argv+=("$a"); a=""; done 2>/dev/null < "$p/cmdline" || true
      [ "${#argv[@]}" -gt 0 ] || continue
      case "${argv[*]-}" in *fluentd*|*td-agent*) ;; *) continue;; esac
      prev=""
      for a in "${argv[@]}"; do
        case "$prev" in -c|--config) echo "$a";; esac
        case "$a" in --config=*) echo "${a#--config=}";; -c=*) echo "${a#-c=}";; esac
        prev="$a"
      done
      { tr '\0' '\n' < "$p/environ"; } 2>/dev/null | sed -n 's/^FLUENT_CONF=//p'
    done
    local skip sk
    while IFS= read -r c; do
      skip=0
      while IFS= read -r sk; do [[ "${c##*/}" == $sk ]] && skip=1; done < <(list_items DET_FLUENTD_SKIP)
      [ "$skip" = 0 ] && [ -r "$c" ] && echo "$c"
    done < <(list_glob DET_FLUENTD_CONFS)
  } | sort -u | while IFS= read -r c; do det_fluentd_expand "$c"; done | sort -u
  return 0
}

# det_fluentd_sources_raw - "path-pattern|pos_file|exclude-patterns" for every `@type tail` source.
# Values may be quoted; strftime placeholders in the path (%Y, %m ...) become *; exclude_path ["a","b"] -> a,b.
det_fluentd_sources_raw() {
  local c
  det_fluentd_confs | while IFS= read -r c; do
    awk '
      function val(s,  k) { sub(/^[ \t]*[a-z_]+[ \t]+/,"",s); sub(/[ \t]+#.*/,"",s); sub(/[ \t]+$/,"",s); gsub(/"/,"",s); gsub(/\047/,"",s); return s }
      /<source>/                       { ins=1; t=0; p=""; pf=""; ex=""; next }
      ins && /@type[ \t]+"?tail"?/     { t=1 }
      ins && /^[ \t]*path[ \t]/        { p=val($0) }
      ins && /^[ \t]*pos_file[ \t]/    { pf=val($0) }
      ins && /^[ \t]*exclude_path[ \t]/ { ex=val($0); gsub(/[\[\] ]/,"",ex) }
      /<\/source>/                     { if (ins && t) print p "|" pf "|" ex; ins=0 }
    ' "$c" 2>/dev/null
  done | while IFS='|' read -r p pf ex; do
    # date codes (path /var/log/app/%Y-%m-%d.log): today's and yesterday's file, not every day's
    if [[ "$p" == *%[A-Za-z]* ]]; then det_expand_dates "$p" | while IFS= read -r one; do printf '%s|%s|%s\n' "$one" "$pf" "$ex"; done
    else printf '%s|%s|%s\n' "$p" "$pf" "$ex"; fi
  done | sort -u
}

# det_fluentd_excluded <file> <exclude-list> - 0 if the file matches one of a source's exclude_path patterns
det_fluentd_excluded() {
  local one; local -a _ex=()
  IFS=',' read -r -a _ex <<<"$2"
  for one in ${_ex[@]+"${_ex[@]}"}; do [ -n "$one" ] && det_glob_match "$1" "$one" && return 0; done
  return 1
}

# det_fluentd_buffers_raw - directories / files fluentd keeps its buffers in (chunks not yet delivered):
# every <buffer> path, and <system> root_dir (where buffers without a path of their own are kept)
det_fluentd_buffers_raw() {
  local c
  det_fluentd_confs | while IFS= read -r c; do
    awk 'function val(s) { sub(/^[ \t]*[a-z_]+[ \t]+/,"",s); sub(/[ \t]+#.*/,"",s); sub(/[ \t]+$/,"",s); gsub(/"/,"",s); gsub(/\047/,"",s); return s }
         /<buffer/ {inb=1; next} /<\/buffer>/ {inb=0}
         /<system>/ {ins=1; next} /<\/system>/ {ins=0}
         inb && /^[ \t]*path[ \t]/     { print val($0) }
         ins && /^[ \t]*root_dir[ \t]/ { print val($0) }' "$c" 2>/dev/null
  done | sort -u
}

# Config parsing is cached for 60 s: a purge pass asks about many files. Refresh in the calling shell
# (not inside a pipeline), so the cache survives for the rest of the pass.
det_cache_refresh() {
  if [ -z "${DET_FL_AT:-}" ] || [ $(( SECONDS - DET_FL_AT )) -ge 60 ]; then
    DET_FL_SRC=$(det_fluentd_sources_raw); DET_FL_BUF=$(det_fluentd_buffers_raw); DET_RS_IN=$(det_rsyslog_inputs_raw)
    DET_RS_OUT=$(det_rsyslog_outputs_raw); DET_RS_RUN=$(det_rsyslog_running)
    DET_FL_AT=$SECONDS
  fi
}
det_fluentd_sources() {
  if [ -n "${DET_FL_AT:-}" ]; then [ -n "$DET_FL_SRC" ] && printf '%s\n' "$DET_FL_SRC"; return 0; fi
  det_fluentd_sources_raw
}

# pg_protected_file <file> - 0 if this file must never be touched even inside a configured path:
# fluentd position files and buffer chunks (not yet delivered), rsyslog queue files, systemd journal,
# anything under a protected system/data directory. Echoes the reason.
pg_protected_file() {
  local f="$1" b bp pos pf bufs
  # cached buffer list inside a pass. An empty list is a valid answer (no fluentd on this server) - it
  # must not trigger a fresh scan of every process for each file (that cost a full CPU on a busy log receiver).
  if [ -n "${DET_FL_AT:-}" ]; then bufs=$DET_FL_BUF; else bufs=$(det_fluentd_buffers_raw); fi
  for b in "${BLOCKED_PATHS[@]}"; do
    [ "$b" = "/" ] && continue
    if [[ "$f" == "$b/"* ]]; then echo "inside protected directory $b"; return 0; fi
  done
  local nm
  while IFS= read -r nm; do
    [[ "${f##*/}" == $nm ]] && { echo "its name matches the protected name '$nm' (setting PG_PROTECT_NAMES)"; return 0; }
  done < <(list_items PG_PROTECT_NAMES)
  while IFS= read -r bp; do
    [ -n "$bp" ] || continue
    bp="${bp%%\**}"; bp="${bp%/}"
    if [ -n "$bp" ] && { [ "$f" = "$bp" ] || [[ "$f" == "$bp"* ]]; }; then echo "a fluentd buffer (logs not yet delivered)"; return 0; fi
  done <<<"$bufs"
  # a fluentd buffer chunk by its name (buffer.b<32 hex>.log, .q..., and their .meta), wherever it is kept -
  # also for buffers whose folder is not written in a config this tool can see
  if [[ "${f##*/}" =~ (^|\.)[bq][0-9a-f]{32}(\.|$) ]]; then echo "a fluentd buffer chunk (logs not yet delivered)"; return 0; fi
  local _ex
  while IFS='|' read -r pos pf _ex; do
    [ -n "$pf" ] && [ "$f" = "$pf" ] && { echo "a fluentd position file"; return 0; }
  done < <(det_fluentd_sources)
  return 1
}

# det_wazuh_patterns - <location> entries of ossec.conf (strftime %x -> *)
det_wazuh_patterns() {
  [ -r "$DET_WAZUH_CONF" ] || return 0
  local p
  det_strip_comments xml < "$DET_WAZUH_CONF" | grep -oE '<location>[^<]+</location>' | sed -E 's#</?location>##g' \
    | while IFS= read -r p; do det_expand_dates "$p"; done
}

# det_wazuh_offset <file> - logcollector's stored read offset (empty if unknown)
det_wazuh_offset() {
  [ -r "$DET_WAZUH_STATUS" ] || return 0
  local p; p=$(printf '%s' "$1" | sed 's/[][\.^$*+?(){}|]/\\&/g')     # the path as literal text, not a regex
  grep -oE "\"path\":\"$p\",\"hash\":\"[0-9a-f]*\",\"offset\":\"[0-9]+\"" "$DET_WAZUH_STATUS" | head -1 | grep -oE '[0-9]+"$' | tr -d '"'
}

# det_logrotate_manages <file> - 0 if any logrotate stanza covers the file
det_logrotate_manages() {
  local f="$1" pat c lrf
  mapfile -t lrf < <(list_glob DET_LOGROTATE_FILES)
  for c in ${lrf[@]+"${lrf[@]}"}; do
    [ -f "$c" ] || continue
    # file names before each "{", also when they are listed one per line above it (the usual rsyslog stanza)
    while IFS= read -r pat; do det_glob_match "$f" "$pat" && return 0; done \
      < <(awk '
            { sub(/#.*/,""); s=$0
              while (length(s)) {
                if (inb) { p=index(s,"}"); if (!p) { s=""; break }; inb=0; s=substr(s,p+1); continue }
                p=index(s,"{"); head=(p ? substr(s,1,p-1) : s)
                n=split(head,a,/[ \t]+/)
                for (i=1;i<=n;i++) { t=a[i]; gsub(/["\047]/,"",t); if (t ~ /^\//) pend[++k]=t }
                if (p) { for (i=1;i<=k;i++) print pend[i]; k=0; inb=1; s=substr(s,p+1) } else s=""
              } }' "$c" 2>/dev/null)
  done
  return 1
}

# det_cleanup_jobs - "where|command" for every cron entry and every ACTIVE systemd timer
det_cleanup_jobs() {
  local f line tm svc ex
  for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
    [ -r "$f" ] || continue
    grep -vE '^[[:space:]]*(#|$)|^[A-Za-z_]+=' "$f" 2>/dev/null | sed "s#^#cron:${f}|#"
  done
  while read -r tm svc; do
    [ -n "$svc" ] && systemctl is-active --quiet "$tm" 2>/dev/null || continue
    ex=$(systemctl show -p ExecStart --value "$svc" 2>/dev/null | grep -oE 'argv\[\]=[^;]+' | sed 's/^argv\[\]=//' | head -1)
    [ -n "$ex" ] && echo "timer:${tm}|${ex}"
  done < <(systemctl list-timers --all --no-legend 2>/dev/null \
           | awk '{t=""; s=""; for (i=1;i<=NF;i++) { if ($i ~ /\.timer$/) t=$i; if ($i ~ /\.service$/) s=$i } if (t!="") print t, s}')
}

# det_path_related <target> <path-token> - 0 when one path contains the other
det_path_related() {
  local t="${1%/}" k="$2"
  k="${k%%[*\$]*}"; k="${k%/}"
  case "$k" in ""|/|/dev*|/proc*|/sys*|/bin*|/sbin*|/usr*|/lib*|/etc*|/tmp|/run*|/var|/var/log|/home|/opt) return 1;; esac
  [ "$t" = "$k" ] || [[ "$t" == "$k/"* ]] || [[ "$k" == "$t/"* ]]
}

# det_job_related <target> <pattern> <path-token> - does a job's path concern the files this path manages?
#   exact file pattern -> the file, its folder or a folder above it
#   wildcard pattern   -> this folder itself, a folder above it, or a file inside it whose name matches the
#                         pattern (another file in the same folder is someone else's business)
det_job_related() {
  local t="${1%/}" pat="$2" k="$3" kk kb
  if [[ "$pat" != *[*?]* ]]; then det_path_related "$t/$pat" "$k"; return; fi
  if [[ "$k" == *[*?]* ]] && [[ "$k" != *\$* ]] && [[ "${k%%[*?]*}" == "$t"* || "$t" == "${k%%[*?]*}"* ]]; then
    # their wildcard: related only if it matches at least one file this path manages
    local mf
    while IFS= read -r mf; do det_glob_match "$mf" "$k" && return 0; done \
      < <(find "$t" -type f -name "$pat" 2>/dev/null | head -50)
    return 1
  fi
  kk="${k%%[*\$]*}"; kk="${kk%/}"
  [ -n "$kk" ] || return 1
  kk=$(realpath -m -s -- "$kk" 2>/dev/null || echo "$kk")     # /var/log/. -> /var/log
  [ "$kk" = "$t" ] && return 0
  case "$kk" in /|/dev*|/proc*|/sys*|/bin*|/sbin*|/usr*|/lib*|/etc*|/tmp|/run*|/var|/var/log|/home|/opt) return 1;; esac
  [[ "$t" == "$kk/"* ]] && return 0
  if [[ "$kk" == "$t/"* ]]; then
    kb="${k##*/}"
    [[ "$kb" == $pat ]] && return 0
    # a sub-folder (paths are searched recursively) counts when it holds files this path manages
    [ -d "$kk" ] && [ -n "$(find "$kk" -type f -name "$pat" -print -quit 2>/dev/null)" ] && return 0
    [[ "$kb" == *[*?]* ]] && [[ "${pat}" == $kb ]] && return 0      # a wildcard of theirs covering our names
  fi
  return 1
}

# det_job_ops <target> <pattern> <text> - the cleaning actions of one job (its command line, then its script)
# that act on this path's files. An action counts only when it and a reference to those files are on the same
# line: the path itself, a variable set to it (VAR=/path, for VAR in /path/*, read VAR from a command on it),
# $1/$@ when the job is started with the path, or a relative name after `cd` into it. An overwrite (> file)
# counts only when its target is such a file; an append (>>) never does. A script that merely looks at the
# path - a health check - and rewrites its own state files elsewhere is not a second cleaner.
# Prints the actions found, space-separated. One awk pass; most jobs never mention the path and return at once.
det_job_ops() {
  local t="$1" pat="$2" text="$3" tok rel="" tre='/[^ "'"'"';|&<>(){}`]+'
  while IFS= read -r tok; do det_job_related "$t" "$pat" "$tok" && rel+="$tok"$'\n'; done \
    < <(grep -oE "$tre" <<<"$text" | sort -u)
  [ -n "$rel" ] || return 0
  LC_ALL=C awk -v rel="$rel" -v tre="$tre" '
    function refs(s,   r, m, v) {     # does s point at the files: a path word, a variable holding one, $1/$@
      r = s
      while (match(r, tre)) { m = substr(r, RSTART, RLENGTH); if (m in R) return 1; r = substr(r, RSTART + RLENGTH) }
      for (v in V) if (match(s, "[$][{]?" v "([^A-Za-z0-9_]|$)")) return 1
      if (pos && match(s, /[$][{]?[1-9@*]/)) return 1
      return 0 }
    BEGIN { n = split(rel, a, "\n"); for (i = 1; i <= n; i++) if (a[i] != "") R[a[i]] = 1 }
    { L[NR] = $0 }
    END {
      for (round = 1; round <= 2; round++)              # two rounds: VAR2=$VAR1/x counts too
        for (i = 1; i <= NR; i++) {
          s = L[i]; name = ""
          if (match(s, /^[ \t]*((export|local|readonly|declare)[ \t]+(-[A-Za-z]+[ \t]+)?)?[A-Za-z_][A-Za-z0-9_]*=/)) {
            name = substr(s, RSTART, RLENGTH - 1); val = substr(s, RSTART + RLENGTH)
            sub(/^[ \t]*((export|local|readonly|declare)[ \t]+(-[A-Za-z]+[ \t]+)?)?/, "", name) }
          else if (match(s, /(^|[ \t;])for[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]+in[ \t]/)) {
            name = substr(s, RSTART, RLENGTH); val = substr(s, RSTART + RLENGTH)
            sub(/^.*for[ \t]+/, "", name); sub(/[ \t].*$/, "", name) }
          else if (match(s, /(^|[ \t;|])read[ \t]+(-[A-Za-z]+[ \t]+)*[A-Za-z_][A-Za-z0-9_]*/)) {
            name = substr(s, RSTART, RLENGTH); val = s; sub(/^.*[ \t]/, "", name) }
          if (name != "" && !(name in V) && refs(val)) V[name] = 1
        }
      pos = refs(L[1])                                  # the job line itself passes the path along
      incd = 0
      for (i = 1; i <= NR; i++) {
        s = L[i]
        if (match(s, /(^|[ \t;&|])cd[ \t]+[^;&|]+/)) { w = substr(s, RSTART, RLENGTH); sub(/^.*cd[ \t]+/, "", w); incd = refs(w) }
        if (incd || refs(s)) {
          if (match(s, /sed[^|;]* -i/)) O["sed -i"] = 1
          if (match(s, /(^|[^A-Za-z0-9_.-])truncate([^A-Za-z0-9_.-]|$)/)) O["truncate"] = 1
          if (match(s, /(^|[^A-Za-z0-9_.-])rm([^A-Za-z0-9_.-]|$)/)) O["rm"] = 1
          if (match(s, /(^|[^A-Za-z0-9_.-])mv([^A-Za-z0-9_.-]|$)/)) O["mv"] = 1
          if (match(s, /(^|[^A-Za-z0-9_.-])shred([^A-Za-z0-9_.-]|$)/)) O["shred"] = 1
          if (match(s, /(^|[^A-Za-z0-9_.-])logrotate([^A-Za-z0-9_.-]|$)/)) O["logrotate"] = 1
          if (match(s, /-delete([^A-Za-z0-9_]|$)/)) O["-delete"] = 1
        }
        r = s                                           # overwrites: the target must be one of the files
        while (match(r, /(^|[^>0-9&])(:[ \t]*)?>[ \t]*"?[^ ;|&)">]+/)) {
          w = substr(r, RSTART, RLENGTH); r = substr(r, RSTART + RLENGTH)
          o = (w ~ /:[ \t]*>/) ? ": >" : "> (overwrite)"; sub(/^.*>[ \t]*"?/, "", w)
          if (refs(w) || (incd && w !~ /^[\/$]/)) O[o] = 1
        }
      }
      for (o in O) printf "%s ", o
    }' <<<"$text"
}

# det_conflicts_report <target> <pattern> - warn about other jobs that also delete / empty / rewrite
# files in this path (cron, timers, logrotate, an older copy of this tool). Two cleaners on one file fight.
det_conflicts_report() {
  local target="$1" pattern="$2" full where cmd text tok n=0 ops
  full="$target"; [[ "$pattern" != *[*?]* ]] && full="$target/$pattern"
  while IFS='|' read -r where cmd; do
    ops=""
    case "$cmd" in
      *purging-console*|*purgingconsole*)
        [[ "$where" == timer:* ]] && ops="another (older) copy of the purging console - it reads the same path list";;
      *)
        text="$cmd"
        for tok in $(grep -oE '/[^ "'"'"';|&<>(){}`]+' <<<"$cmd"); do
          [ -f "$tok" ] && [ "$(stat -c %s "$tok" 2>/dev/null || echo 0)" -lt 2000000 ] && grep -qI . "$tok" 2>/dev/null && text+=$'\n'"$(grep -vE '^[[:space:]]*#' "$tok")"     # comments are not actions
        done
        ops=$(det_job_ops "$target" "$pattern" "$text");;
    esac
    [ -n "$ops" ] || continue
    [ "$n" = 0 ] && echo "${C_YELLOW}warning:${C_RESET} other jobs also clean ${C_BOLD}${full}$([[ "$pattern" == *[*?]* ]] && echo " ($pattern)")${C_RESET} - two cleaners on one file can lose or corrupt logs:"
    n=$(( n + 1 ))
    printf "   %s %s\n      runs: %s\n      does: %s\n" "$(dot "$C_YELLOW")" "${where#*:}" "${cmd:0:160}" "$ops"
  done < <(det_cleanup_jobs)
  # logrotate: the file itself, or (for a pattern) the first matching files in the folder
  local lr="" x
  if [ -f "$full" ]; then det_logrotate_manages "$full" && lr="$full"
  elif [ -d "$target" ]; then
    while IFS= read -r -d '' x; do det_logrotate_manages "$x" && { lr="$x"; break; }; done \
      < <(find "$target" -type f -name "$pattern" -print0 2>/dev/null | head -z -n 20)
  fi
  if [ -n "$lr" ]; then
    [ "$n" = 0 ] && echo "${C_YELLOW}warning:${C_RESET} other jobs also clean ${C_BOLD}${full}${C_RESET}:"
    n=$(( n + 1 )); printf "   %s logrotate is configured for %s\n" "$(dot "$C_YELLOW")" "$([ "$lr" = "$full" ] && echo "this file" || echo "$lr")"
  fi
  [ "$n" -gt 0 ] && echo "   ${C_DIM}Disable the other job (or remove this path) so only one of them manages it.${C_RESET}"
  return 0
}

# det_deleted_open - "size|pid|name|path|pos|mode" for files that were deleted but are still held open by a
# process: their disk space is NOT freed until that process closes them (and it may be stuck on them).
# pos = how far that process has read; mode = r (reading) or w (writing to it).
det_deleted_open() {
  local fd l pid sz r ok sk roots skips
  mapfile -t roots < <(list_items PG_HELD_ROOTS); mapfile -t skips < <(list_items PG_HELD_SKIP)
  find /proc/[0-9]*/fd -maxdepth 1 -type l -printf '%p\t%l\n' 2>/dev/null | awk -F'\t' '$2 ~ / \(deleted\)$/' \
  | while IFS=$'\t' read -r fd l; do
      l="${l% (deleted)}"
      ok=0; for r in ${roots[@]+"${roots[@]}"}; do [[ "$l" == ${r%/}/* ]] && { ok=1; break; }; done
      [ "$ok" = 1 ] || continue
      for sk in ${skips[@]+"${skips[@]}"}; do [[ "$l" == $sk ]] && { ok=0; break; }; done
      [ "$ok" = 1 ] || continue
      pid=${fd#/proc/}; pid=${pid%%/*}
      sz=$(stat -L -c %s "$fd" 2>/dev/null || echo 0); [ "$sz" -gt 0 ] || continue
      local inf="/proc/$pid/fdinfo/${fd##*/}" pos fl md=r
      pos=$(awk '/^pos:/ {print $2}' "$inf" 2>/dev/null); fl=$(awk '/^flags:/ {print $2}' "$inf" 2>/dev/null)
      [ -n "$fl" ] && [ $(( 8#$fl & 3 )) -ne 0 ] && md=w
      echo "$sz|$pid|$(cat "/proc/$pid/comm" 2>/dev/null)|$l|${pos:-0}|$md"
    done | sort -t'|' -k1,1nr | awk -F'|' '!seen[$2 "|" $4]++'
}

det_deleted_open_report() {
  local sz pid comm p pos md n=0 st
  while IFS='|' read -r sz pid comm p pos md; do
    [ "$n" = 0 ] && echo "${C_YELLOW}Deleted files still held open${C_RESET} ${C_DIM}(disk not freed until the process lets go; restarting it releases the file - check the last column first)${C_RESET}"
    n=$(( n + 1 ))
    if [ "$md" = w ]; then st="${C_YELLOW}still WRITING to it - what it writes now is lost when it closes; restart it to make it write to the current file${C_RESET}"
    elif [ "${pos:-0}" -ge "$sz" ]; then st="${C_GREEN}read to the end - safe to restart${C_RESET}"
    else st="${C_RED}$(human $(( sz - pos ))) NOT READ YET - restarting it now loses that part${C_RESET}"; fi
    printf "   %-8s %-18s %s\n            %b\n" "$(human "$sz")" "$comm($pid)" "$p" "$st"
  done < <(det_deleted_open)
  [ "$n" = 0 ] && echo "${C_DIM}No deleted log files are being held open.${C_RESET}"
  return 0
}

# det_file_report <file> - human-readable facts about one file
det_file_report() {
  local f="$1" size kind=LIVE line pid comm k rw app pos
  size=$(stat -c %s "$f" 2>/dev/null || echo 0)
  if pg_rotated_name "${f##*/}"; then kind=ROTATED; elif pg_dated_name "${f##*/}"; then kind=DATE-NAMED; fi
  printf "%s%s%s  %s  %s\n" "$C_BOLD" "$f" "$C_RESET" "$(human "$size")" "$kind"
  local pwhy; pwhy=$(pg_protected_file "$f") && printf "   %sPROTECTED: %s - the purge engine never touches it%s\n" "$C_YELLOW" "$pwhy" "$C_RESET"

  local found=0 pat src
  declare -A rd_pos=() rd_comm=() rd_kind=() wr_seen=()
  while IFS='|' read -r pid comm k rw app pos; do
    [ -n "$pid" ] || continue; found=1
    if [ "$rw" = "r" ]; then
      # a process may hold the same file open twice (rsyslog does) - keep its furthest position
      if [ -z "${rd_pos[$pid]:-}" ] || [ "$pos" -gt "${rd_pos[$pid]}" ]; then rd_pos[$pid]=$pos; fi
      rd_comm[$pid]=$comm; rd_kind[$pid]=$k
    else
      [ -n "${wr_seen[$pid]:-}" ] && continue; wr_seen[$pid]=1
      printf "   writer  %-9s pid=%-7s %-16s %s\n" "$k" "$pid" "$comm" \
        "$([ "$app" = 1 ] && echo "append-mode" || echo "${C_YELLOW}NOT append-mode${C_RESET}")"
    fi
  done < <(det_proc_users "$f")
  for pid in "${!rd_pos[@]}"; do
    local lag=$(( size - rd_pos[$pid] )); [ "$lag" -lt 0 ] && lag=0
    printf "   reader  %-9s pid=%-7s %-16s offset=%s  behind=%s\n" "${rd_kind[$pid]}" "$pid" "${rd_comm[$pid]}" "${rd_pos[$pid]}" "$(human "$lag")"
  done
  [ "$found" = 0 ] && printf "   %sno process currently holds it open%s\n" "$C_DIM" "$C_RESET"

  # configured-but-not-open consumers (config says they read it)
  while IFS= read -r pat; do
    det_glob_match "$f" "$pat" && printf "   config  rsyslog   imfile pattern: %s\n" "$pat"
  done < <(det_rsyslog_patterns)
  while IFS='|' read -r pat src excl; do
    local p2 one
    IFS=',' read -ra _arr <<<"$pat"
    for one in "${_arr[@]}"; do
      one="${one// /}"
      if det_glob_match "$f" "$one" && ! det_fluentd_excluded "$f" "$excl"; then
        local off=""
        if [ -r "$src" ]; then
          off=$(awk -F'\t' -v p="$f" '$1==p {print $2}' "$src" 2>/dev/null | head -1)
          # ffffffffffffffff is fluentd's "no longer watched" marker, not a real offset
          if [ "$off" = "ffffffffffffffff" ]; then off="unwatched"; elif [ -n "$off" ]; then off=$(( 16#$off )); fi
        fi
        printf "   config  fluentd   tail pattern: %s  pos_file=%s%s\n" "$one" "${src:-none}" "${off:+  stored-offset=$off}"
      fi
    done
  done < <(det_fluentd_sources)
  while IFS= read -r pat; do
    if det_glob_match "$f" "$pat"; then
      local woff; woff=$(det_wazuh_offset "$f")
      printf "   config  wazuh     localfile: %s%s\n" "$pat" "${woff:+  stored-offset=$woff}"
    fi
  done < <(det_wazuh_patterns)
  det_logrotate_manages "$f" && printf "   config  logrotate manages this file\n"
  case "$f" in /var/ossec/logs/*) printf "   config  wazuh     Wazuh log path (Wazuh also rotates/compresses it on its own schedule)\n";; esac
  local nl; nl=$(stat -c %h "$f" 2>/dev/null || echo 1)
  [ "$nl" -gt 1 ] && printf "   config  hard-linked: %s names share this file (find them: find / -xdev -samefile %s)\n" "$nl" "$f"
}

# detect_report <file|dir> - report on one file, or every regular file under a directory
detect_report() {
  local t="${1:-}" f why
  [ -n "$t" ] || { echo "usage: purgingconsole --detect <file|dir>"; return 1; }
  [ -e "$t" ] || { echo "no such path: $t"; return 1; }
  det_cache_refresh
  if [ -d "$t" ]; then
    while IFS= read -r -d '' f; do det_file_report "$f"; echo; done < <(find "$t" -type f -print0 2>/dev/null | sort -z)
    det_conflicts_report "${t%/}" "*"
  else
    det_file_report "$t"
    det_conflicts_report "$(dirname "$t")" "$(basename "$t")"
  fi
}

# ============================================================
# SECTION: Worker (purge execution engine)
# ============================================================

# with_lock <fn> [args...] - serializes worker runs so a manual purge and
# the background watcher never truncate the same file concurrently.
with_lock() {
  mkdir -p "$CONF_DIR" 2>/dev/null
  # the braces keep "2>/dev/null" to this one line: a bare "exec 9>f 2>/dev/null" would silence stderr for the
  # rest of the process (invisible menu prompts, and service errors missing from the journal)
  { exec 9>"$LOCK_FILE"; } 2>/dev/null
  # PG_LOCK_WAIT>0 (manual purges) waits for a running pass instead of silently skipping it
  if [ "${PG_LOCK_WAIT:-0}" -gt 0 ]; then
    if ! flock -w "$PG_LOCK_WAIT" 9 2>/dev/null; then
      log_warn "manual run gave up - the background pass held the lock for ${PG_LOCK_WAIT}s"; echo "${C_YELLOW}Another purge pass is still running; try again shortly.${C_RESET}"
      return 1
    fi
  elif ! flock -n 9 2>/dev/null; then
    [ -n "${PG_LOCK_QUIET:-}" ] || log_warn "worker run skipped - another instance already holds the lock"
    return 0
  fi
  "$@"
  local rc=$?
  flock -u 9 2>/dev/null
  return $rc
}

do_watch() {
  log_info "realtime watcher started (purge pass every $(human_secs "$PG_PASS_SEC"), rotated-copy readers checked every $(human_secs "$PG_TICK_SEC"))"
  local _hb=0 _last=-999999 _beat=$SECONDS
  # A stop (systemctl stop/restart, Ctrl-C) only sets PG_STOP: exiting at once could land between moving a
  # live file and telling its writer to reopen. The current file is finished, the rest of the pass is left
  # for the next start (see purge_one_path), then the watcher exits.
  PG_STOP=""
  trap 'PG_STOP=1' TERM INT
  while true; do
    settings_reload_if_changed
    if [ $(( SECONDS - _last )) -ge "$PG_PASS_SEC" ]; then
      _last=$SECONDS
      PG_LOCK_QUIET=1 with_lock do_worker     # a manual purge holding the lock is normal, not worth a warning
      _hb=$(( _hb + 1 ))
    elif compgen -G "$PG_WATCH_DIR/*.watch" >/dev/null 2>&1; then
      PG_LOCK_QUIET=1 with_lock pg_watch_all
    fi
    if [ $(( SECONDS - _beat )) -ge 3600 ]; then _beat=$SECONDS; log_info "watcher alive - ${_hb} purge passes so far"; fi
    [ -n "$PG_STOP" ] || pg_auto_update_tick
    [ -n "$PG_STOP" ] && break
    sleep "$PG_TICK_SEC" & wait $! 2>/dev/null    # wait (not a plain sleep) lets a stop interrupt the pause
    [ -n "$PG_STOP" ] && break
  done
  log_info "realtime watcher stopping"
  exit 0
}

# pg_noterm <command...> - run it with TERM/INT ignored (children inherit that), so a service stop cannot
# cut it short half-way. The stop itself still reaches the watcher, which acts on it afterwards.
pg_noterm() { ( trap '' TERM INT; "$@" ); }
# pg_recreate <file> <mode> <uid> <gid> - the empty live file again, right after a rotation
pg_recreate() {
  if ( set -C; : > "$1" ) 2>/dev/null; then chmod "$2" "$1" 2>/dev/null; chown "$3:$4" "$1" 2>/dev/null; fi
  return 0
}

# ============================================================
# SECTION: Safe Purge Engine
# ============================================================
# Per-file decision + action, built on the detection layer above:
#   rotated / old file -> delete once no process holds it open and readers are past it
#   live file          -> ROTATE + reload writer(s)              (preferred)
#                      -> TRUNCATE in place                      (fallback: every writer is append-mode
#                                                                 and none of them can be reloaded)
#                      -> SKIP + warn                            (unsafe: non-append writer that can't be
#                                                                 reloaded, or a reader that is down/unknown)
# A live file is rotated only when every reader is at its end, or - if some are behind - only when
# all of them hold it open (so they drain the renamed copy) and the watch & replay layer below covers
# a reader that crashes before finishing. Our rotated copies (in the copy folder, named with their delete
# time - see "Copy folder" below; older ones <file>.purge-<epoch>) are deleted only at their delete time,
# once no process holds them and their watch record is closed.
PG_ROTATED_RE='(\.(gz|xz|bz2|zst|old|sum)|\.[0-9]+|\.purge-[0-9]+|-[0-9]{8})$'
# Date-named files: a writer that names its files by date (20261029.log.jsonl, app.log.2026-10-29,
# firewall_20261029_091630.log, Wazuh's archives/2026/Oct/ossec-archive-29.json) has moved on to a new
# file once the day is over. They are handled like rotated files: deleted when older than the retention,
# only if no process holds them and every reader's stored position is at their end.
PG_DATED_RE='(^|[^0-9])(19|20)[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])([^0-9]|$)|(^|[^0-9])(19|20)[0-9]{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])([^0-9]|$)|^ossec-(archive|alerts|firewall|totals)-[0-9]{1,2}\.(json|log)$'
# extra name patterns from the settings (PG_ROTATED_EXTRA / PG_DATED_EXTRA)
pg_rotated_name() {
  [[ "$1" =~ $PG_ROTATED_RE ]] && return 0
  local re; while IFS= read -r re; do [[ "$1" =~ $re ]] && return 0; done < <(list_items PG_ROTATED_EXTRA)
  return 1
}
pg_dated_name() {
  [[ "$1" =~ $PG_DATED_RE ]] && return 0
  local re; while IFS= read -r re; do [[ "$1" =~ $re ]] && return 0; done < <(list_items PG_DATED_EXTRA)
  return 1
}
pg_old_name() { pg_rotated_name "$1" || pg_dated_name "$1"; }
# Wazuh rotates its own logs at midnight: nothing under PG_QUIET_PREFIXES is touched between
# PG_QUIET_FROM and PG_QUIET_TO (both settings; the window may run past midnight).
pg_in_quiet_window() {
  local p hm from=$(( 10#$PG_QUIET_FROM )) to=$(( 10#$PG_QUIET_TO ))
  [ "$from" != "$to" ] || return 1
  while IFS= read -r p; do
    [[ "$1" == "$p"* ]] || continue
    hm=$(( 10#${PG_NOW_HHMM:-$(date +%H%M)} ))
    if [ "$from" -gt "$to" ]; then [ "$hm" -ge "$from" ] || [ "$hm" -lt "$to" ]; else [ "$hm" -ge "$from" ] && [ "$hm" -lt "$to" ]; fi
    return
  done < <(list_items PG_QUIET_PREFIXES)
  return 1
}
# (all tunables - hold time, disk limit, truncation, lag limits, timings - are settings; see the Settings section)
PG_ASIDE_DIR="/var/lib/purging-console/aside"
declare -A PG_SKIP_SEEN=() PG_NEXT_TRY=()
PG_WHY=""; PG_FREED=0; PG_OUTCOME="idle"; PG_LIVE=""
PG_UNREAD=0; PG_UNREAD_STORED=0; PG_BLOCK=""; PG_STALE=0; PG_LAG=0
PG_WRITERS=0; PG_ALL_APPEND=1; PG_UNRELOADABLE=0; PG_RELOAD_CMDS=(); PG_WRITER_CONF=""
PG_COPY_DUE=""; PG_COPY_REC=""; PG_DEST=""; PG_DEST_DIR=""
DET_RS_OUT=""; DET_RS_RUN=0

# pg_skip <file> <why> - remember the reason, log it once per distinct reason, back off retries
pg_skip() {
  PG_WHY="$2"
  PG_NEXT_TRY["$1"]=$(( $(date +%s) + PG_RETRY_SEC ))
  if [ "${PG_SKIP_SEEN[$1]:-}" != "$2" ]; then PG_SKIP_SEEN["$1"]="$2"; [ -n "${PG_PLAN_QUIET:-}" ] || log_warn "skip $1 - $2"; fi
}

# pg_say <color> <file> <text> - one verbose line per file
pg_say() { printf "  %b %s  ${C_DIM}->${C_RESET} %s\n" "$(dot "$1")" "$2" "$3"; }

# pg_lag_of <file> <reader-position> - sets PG_LAG (bytes that reader still has to read) and PG_STALE.
# The size is read *after* the position was obtained: a file only grows, so on a live writer
# size >= position always holds. A position beyond EOF therefore means the file really shrank or
# was replaced and that reader has not noticed yet - it has read none of the current content.
pg_lag_of() {
  local size; size=$(stat -c %s "$1" 2>/dev/null || echo 0)
  if [ "$2" -gt "$size" ]; then PG_LAG=$size; PG_STALE=1; else PG_LAG=$(( size - $2 )); fi
}

# pg_consumers_check <file> - sets PG_UNREAD (most bytes any reader still has to read)
# and PG_BLOCK (non-empty = a configured reader is down/unknown, so purging is unsafe).
pg_consumers_check() {
  local f="$1" pid comm k rw app pos key lag pat src one off
  det_cache_refresh
  local have_rsys=0 have_fl=0 have_wz=0
  declare -A kp=()
  PG_UNREAD=0; PG_UNREAD_STORED=0; PG_BLOCK=""; PG_STALE=0; PG_LAG=0
  while IFS='|' read -r pid comm k rw app pos; do
    [ -n "$pid" ] && [ "$rw" = "r" ] || continue
    key="$k:$pid"
    if [ -z "${kp[$key]:-}" ] || [ "$pos" -gt "${kp[$key]}" ]; then kp[$key]=$pos; fi
  done < <(det_proc_users "$f")
  for key in "${!kp[@]}"; do
    pg_lag_of "$f" "${kp[$key]}"; lag=$PG_LAG
    [ "$lag" -gt "$PG_UNREAD" ] && PG_UNREAD=$lag
    case "$key" in rsyslog:*) have_rsys=1;; fluentd:*) have_fl=1;; wazuh:*) have_wz=1;; esac
  done

  # Consumers that are configured to read this file but are not holding it open:
  # fall back to their stored offset; if there is none we cannot prove they are done.
  if [ "$have_rsys" = 0 ]; then
    while IFS= read -r pat; do
      if det_glob_match "$f" "$pat"; then PG_BLOCK="rsyslog imfile is configured for this file but is not reading it"; break; fi
    done < <(det_rsyslog_patterns)
  fi
  if [ "$have_fl" = 0 ] && [ -z "$PG_BLOCK" ]; then
    while IFS='|' read -r pat src excl; do
      IFS=',' read -ra _pg_a <<<"$pat"
      for one in "${_pg_a[@]}"; do
        one="${one// /}"
        det_glob_match "$f" "$one" || continue
        det_fluentd_excluded "$f" "$excl" && continue      # exclude_path: fluentd never reads it
        off=""; local fino="" ino po pi
        # pos_file lines: path<TAB>pos(hex)<TAB>inode(hex). Prefer the entry for this file's inode;
        # an entry for another inode is a position in an older file - it has read none of this one.
        if [ -r "$src" ]; then
          ino=$(stat -c %i "$f" 2>/dev/null)
          while read -r po pi; do
            [[ "$po" =~ ^[0-9a-fA-F]+$ ]] || continue
            off=$po; fino=$pi
            [[ "$pi" =~ ^[0-9a-fA-F]+$ ]] && [ -n "$ino" ] && [ "$(( 16#$pi ))" = "$ino" ] && break
          done < <(awk -F'\t' -v p="$f" '$1==p {print $2, $3}' "$src" 2>/dev/null)
        fi
        local other_ino=0
        [[ "$fino" =~ ^[0-9a-fA-F]+$ ]] && [ -n "$ino" ] && [ "$(( 16#$fino ))" != "$ino" ] && other_ino=1
        # "unwatched" counts only for this very file (same inode). An unwatched entry left by an older file
        # under the same name says nothing about this one, which fluentd has not read yet.
        if [ "$off" = "ffffffffffffffff" ] && [ "$other_ino" = 0 ]; then continue    # fluentd no longer watches it
        elif [ -n "$off" ]; then
          if [ "$other_ino" = 1 ]; then
            lag=$(stat -c %s "$f" 2>/dev/null || echo 0); PG_STALE=1
          else
            pg_lag_of "$f" $(( 16#$off )); lag=$PG_LAG
          fi
          [ "$lag" -gt "$PG_UNREAD" ] && PG_UNREAD=$lag
          [ "$lag" -gt "$PG_UNREAD_STORED" ] && PG_UNREAD_STORED=$lag
        else PG_BLOCK="fluentd tail is configured for this file but has no stored position (not running / never read it)"; fi
      done
    done < <(det_fluentd_sources)
  fi
  if [ "$have_wz" = 0 ] && [ -z "$PG_BLOCK" ]; then
    while IFS= read -r pat; do
      det_glob_match "$f" "$pat" || continue
      off=$(det_wazuh_offset "$f")
      if [ -n "$off" ]; then
        pg_lag_of "$f" "$off"; lag=$PG_LAG
        [ "$lag" -gt "$PG_UNREAD" ] && PG_UNREAD=$lag
        [ "$lag" -gt "$PG_UNREAD_STORED" ] && PG_UNREAD_STORED=$lag
      else PG_BLOCK="Wazuh localfile is configured for this file but logcollector has no stored offset"; break; fi
    done < <(det_wazuh_patterns)
  fi
  return 0
}

# pg_truncate_blockers <file> - echoes why truncating in place would break a reader (empty = safe).
# fluentd in_tail and the Wazuh logcollector restart from the top when a file shrinks (Wazuh can take up to
# ~64s to notice); rsyslog imfile only does so with reopenOnTruncate="on" - otherwise it silently stops reading.
pg_truncate_blockers() {
  local f="$1" pid comm k rw app pos pat re ok
  declare -A seen=()
  while IFS='|' read -r pid comm k rw app pos; do
    [ -n "$pid" ] && [ "$rw" = "r" ] || continue
    [ -n "${seen[$k:$pid]:-}" ] && continue; seen[$k:$pid]=1
    case "$k" in
      fluentd|wazuh) ;;     # both re-sync after a shrink (Wazuh only at its next file check - see pg_consumers_check)
      rsyslog)
        ok=0
        while IFS='|' read -r pat re; do
          if det_glob_match "$f" "$pat" && [ "$re" = "on" ]; then ok=1; fi
        done < <(det_rsyslog_inputs)
        if [ "$ok" != "1" ]; then echo "rsyslog imfile does not follow truncation (reopenOnTruncate is off) - it would stop reading this file"; return 0; fi;;
      *)
        pg_known_reader "$k" "$comm" || { echo "reader '$comm' (pid $pid) is not known to follow truncation (setting PG_READERS)"; return 0; };;
    esac
  done < <(det_proc_users "$f")
}

# pg_finished_file_check <file> - may a finished (rotated / date-named) file be deleted now? 0 = yes.
# Readers such as fluentd keep every watched file open, even long-finished ones, so "open" alone is not a
# reason to wait. It is safe when: nobody has it open for writing; every process reading it is a known
# log reader whose read position is at the end; every saved reader position (fluentd pos_file) is at the
# end; and no configured reader of it is down. Sets PG_WHY when not.
pg_finished_file_check() {
  local f="$1" size pid comm k rw app pos pat src one off ino po pi
  size=$(stat -c %s "$f" 2>/dev/null || echo 0)
  while IFS='|' read -r pid comm k rw app pos; do
    [ -n "$pid" ] || continue
    if [ "$rw" != "r" ]; then PG_WHY="still open for writing by $comm (pid $pid)"; return 1; fi
    pg_known_reader "$k" "$comm" || { PG_WHY="open by $comm (pid $pid), which is not a known log reader (setting PG_READERS)"; return 1; }
    if [ "$pos" -lt "$size" ]; then PG_WHY="$comm (pid $pid) is still reading it ($(human $(( size - pos ))) unread)"; return 1; fi
  done < <(DET_BY_INODE=1 det_proc_users "$f")     # by inode: also readers that opened it under a removed name
  # saved positions: fluentd may have read data into memory that it has not processed yet
  ino=$(stat -c %i "$f" 2>/dev/null)
  while IFS='|' read -r pat src excl; do
    [ -r "$src" ] || continue
    IFS=',' read -ra _pf_a <<<"$pat"
    for one in "${_pf_a[@]}"; do
      one="${one// /}"
      det_glob_match "$f" "$one" || continue
      det_fluentd_excluded "$f" "$excl" && continue
      while read -r po pi; do
        [[ "$po" =~ ^[0-9a-fA-F]+$ ]] || continue
        [ "$po" = "ffffffffffffffff" ] && continue
        [[ "$pi" =~ ^[0-9a-fA-F]+$ ]] && [ -n "$ino" ] && [ "$(( 16#$pi ))" != "$ino" ] && continue
        if [ "$(( 16#$po ))" -lt "$size" ]; then PG_WHY="fluentd's saved position is $(human $(( size - 16#$po ))) short of the end"; return 1; fi
      done < <(awk -F'\t' -v p="$f" '$1==p {print $2, $3}' "$src" 2>/dev/null)
    done
  done < <(det_fluentd_sources)
  pg_consumers_check "$f"
  if [ -n "$PG_BLOCK" ]; then PG_WHY="$PG_BLOCK"; return 1; fi
  if [ "$PG_UNREAD" -gt 0 ]; then PG_WHY="readers have not finished it ($(human "$PG_UNREAD") unread)"; return 1; fi
  return 0
}

# pg_reload_cmd_for <pid> <kind> - echoes the safe way to make that writer reopen its files
pg_reload_cmd_for() {
  local pid="$1" k="$2" unit
  if [ "$k" = "rsyslog" ]; then echo "systemctl kill -s HUP rsyslog.service"; return 0; fi
  unit=$(sed -nE 's#.*/([^/]+\.service)$#\1#p' "/proc/$pid/cgroup" 2>/dev/null | head -1)
  [ -n "$unit" ] || return 1
  [ -n "$(systemctl show -p ExecReload --value "$unit" 2>/dev/null)" ] || return 1   # never blind-HUP: default action kills
  echo "systemctl reload $unit"
}

# pg_writers_check <file> - sets PG_WRITERS, PG_ALL_APPEND, PG_UNRELOADABLE, PG_RELOAD_CMDS, PG_WRITER_CONF.
# A file that no process holds open but that a running rsyslog writes by its config counts as written by
# rsyslog (PG_WRITER_CONF=rsyslog): rsyslog opens it by name at its next write, so it is rotated like any
# rsyslog file. Deciding "nobody writes it" between two bursts left busy firewall logs unrotated for a day.
pg_writers_check() {
  local pid comm k rw app pos cmd
  declare -A seen=() cmdseen=()
  PG_WRITERS=0; PG_ALL_APPEND=1; PG_UNRELOADABLE=0; PG_RELOAD_CMDS=(); PG_WRITER_CONF=""
  while IFS='|' read -r pid comm k rw app pos; do
    [ -n "$pid" ] && [ "$rw" != "r" ] || continue
    [ -n "${seen[$pid]:-}" ] && continue; seen[$pid]=1
    PG_WRITERS=$(( PG_WRITERS + 1 ))
    [ "$app" = "1" ] || PG_ALL_APPEND=0
    if cmd=$(pg_reload_cmd_for "$pid" "$k"); then
      if [ -z "${cmdseen[$cmd]:-}" ]; then cmdseen[$cmd]=1; PG_RELOAD_CMDS+=("$cmd"); fi
    else
      PG_UNRELOADABLE=1
    fi
  done < <(det_proc_users "$1")
  if [ "$PG_WRITERS" -eq 0 ] && det_rsyslog_writes "$1"; then
    PG_WRITERS=1; PG_WRITER_CONF=rsyslog; PG_RELOAD_CMDS=("$(pg_reload_cmd_for 0 rsyslog)")
  fi
  return 0
}

# pg_wait_caught_up <file> - 0 once every reader is at EOF; 1 on timeout / blocked
pg_wait_caught_up() {
  local t=0
  while :; do
    pg_consumers_check "$1"
    if [ -n "$PG_BLOCK" ]; then PG_WHY="$PG_BLOCK"; return 1; fi
    [ "$PG_UNREAD" -eq 0 ] && return 0
    if [ "$t" -ge "$PG_CATCHUP_SEC" ]; then PG_WHY="readers still $(human "$PG_UNREAD") behind after ${PG_CATCHUP_SEC}s"; return 1; fi
    sleep 1; t=$(( t + 1 ))
  done
}

# pg_known_reader <kind> <comm> - rsyslog / fluentd / wazuh, or a program on the PG_READERS list
pg_known_reader() {
  case "$1" in rsyslog|fluentd|wazuh) return 0;; esac
  local r; while IFS= read -r r; do [ "$2" = "$r" ] && return 0; done < <(list_items PG_READERS)
  return 1
}

# pg_readers_drain <file> - 0 if every reader holding the file is one known to finish a renamed inode
pg_readers_drain() {
  local pid comm k rw app pos
  while IFS='|' read -r pid comm k rw app pos; do
    [ "$rw" = "r" ] || continue
    pg_known_reader "$k" "$comm" || return 1
  done < <(det_proc_users "$1")
  return 0
}

# ============================================================
# SECTION: Watch & replay (protects readers that crash after a rotation)
# ============================================================
# After a rotation the readers that had the file open keep reading the renamed copy
# (<file>.purge-<epoch>). A reader that exits or closes it before the end would never come back
# to it - a restarted reader reopens the file by its normal name. So every rotation first writes a
# watch record (reader pid + start time + read position), and each watcher tick checks it:
#   reader still holds the copy   -> track its position; done when it reaches the end
#   reader closed it, or exited   -> done if it had reached the end; otherwise ABANDONED
#   abandoned                     -> the unread tail of the copy is appended to the live file, starting
#                                    at a line boundary, in one write() so it cannot interleave with a
#                                    writer's lines. The restarted reader reads it there. Readers that had
#                                    already read it see those lines twice: duplicates, never loss.
# A copy is never deleted while its watch record is open, nor while any process holds it open.
PG_WATCH_DIR="/var/lib/purging-console/watch"
PG_PENDING_DIR="/var/lib/purging-console/pending"   # per path: live files deferred and retried every pass
PG_COPIES_DIR="/var/lib/purging-console/copies"     # one record per rotated copy in a copy folder: its delete time

# pg_pid_start <pid> - process start time (field 22 of /proc/<pid>/stat); tells a restarted pid apart
pg_pid_start() {
  local s; s=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
  s=${s##*) }
  set -- $s
  echo "${20}"
}

# pg_readers_snapshot <file> - "kind|pid|start|comm|pos" for every process reading it (furthest fd)
pg_readers_snapshot() {
  local pid comm k rw app pos st
  declare -A mp=() kc=() cm=()
  while IFS='|' read -r pid comm k rw app pos; do
    [ -n "$pid" ] && [ "$rw" = "r" ] || continue
    if [ -z "${mp[$pid]:-}" ] || [ "$pos" -gt "${mp[$pid]}" ]; then mp[$pid]=$pos; fi
    kc[$pid]=$k; cm[$pid]=${comm//[|=]/_}
  done < <(det_proc_users "$1")
  for pid in "${!mp[@]}"; do
    st=$(pg_pid_start "$pid") || continue
    echo "${kc[$pid]}|$pid|$st|${cm[$pid]}|${mp[$pid]}"
  done
}

pg_watch_rec() { echo "$PG_WATCH_DIR/$(path_id "$1").watch"; }   # <copy> -> record path
pg_watch_open() { [ -e "$(pg_watch_rec "$1")" ]; }                # <copy> still watched?

pg_watch_load() {
  local k v
  PG_W_COPY=""; PG_W_LIVE=""; PG_W_CREATED=0; PG_W_ROWS=()
  while IFS='=' read -r k v; do
    case "$k" in COPY) PG_W_COPY=$v;; LIVE) PG_W_LIVE=$v;; CREATED) PG_W_CREATED=$v;; R) PG_W_ROWS+=("$v");; esac
  done < "$1"
  [ -n "$PG_W_COPY" ] && [ -n "$PG_W_LIVE" ]
}

pg_watch_save() {   # atomic: a crash mid-write never leaves a torn record
  local tmp="$1.tmp.$$" r
  { echo "V=1"; echo "COPY=$PG_W_COPY"; echo "LIVE=$PG_W_LIVE"; echo "CREATED=$PG_W_CREATED"
    for r in ${PG_W_ROWS[@]+"${PG_W_ROWS[@]}"}; do echo "R=$r"; done; } > "$tmp" && mv -f "$tmp" "$1"
}

# pg_watch_create <copy> <live> <snapshot> - written BEFORE the rename, so a crash of this tool
# between rename and bookkeeping can never leave an unwatched copy. rc 1 = could not write it.
pg_watch_create() {
  local line
  [ -n "$3" ] || return 0
  mkdir -p "$PG_WATCH_DIR" 2>/dev/null && chmod 700 "$PG_WATCH_DIR" 2>/dev/null || return 1
  PG_W_COPY=$1; PG_W_LIVE=$2; PG_W_CREATED=$(date +%s); PG_W_ROWS=()
  while IFS= read -r line; do [ -n "$line" ] && PG_W_ROWS+=("$line|watching"); done <<<"$3"
  pg_watch_save "$(pg_watch_rec "$1")"
}

# pg_replay <copy> <live> <from> - append copy[from..end] to live (see section header). rc 1 = retry later.
pg_replay() {
  local copy="$1" live="$2" start="$3" size pre nl len free b t=0 add=0
  size=$(stat -c %s "$copy" 2>/dev/null) || { PG_WHY="copy $copy vanished"; return 1; }
  [ "$start" -lt "$size" ] || return 0
  if [ "$start" -gt 0 ]; then
    # back up to the start of the line containing <from>: a repeated half line beats a lost one
    pre=$(( start < 65536 ? start : 65536 ))
    nl=$(dd if="$copy" iflag=skip_bytes,count_bytes skip=$(( start - pre )) count="$pre" status=none 2>/dev/null \
         | od -An -v -tx1 -w1 | grep -n '0a' | tail -1 | cut -d: -f1)
    start=$(( start - pre + ${nl:-0} ))
  fi
  len=$(( size - start ))
  [ "$(tail -c 1 "$copy" | od -An -tx1 | tr -d ' \n')" = "0a" ] || add=1   # end the replay on a newline
  [ -e "$live" ] || { PG_WHY="live file $live is missing - waiting for its writer to recreate it"; return 1; }
  free=$(df --output=avail -B1 "$live" 2>/dev/null | tail -1 | tr -dc '0-9')
  if [ "${free:-0}" -lt $(( len + PG_REPLAY_MARGIN )) ]; then PG_WHY="not enough free disk to replay $(human "$len") - copy kept"; return 1; fi
  # do not land in the middle of a line a writer is still writing
  while [ "$t" -lt 40 ]; do
    b=$(tail -c 1 "$live" 2>/dev/null | od -An -tx1 | tr -d ' \n')
    if [ -z "$b" ] || [ "$b" = "0a" ]; then break; fi
    sleep 0.05; t=$(( t + 1 ))
  done
  { tail -c +$(( start + 1 )) "$copy"; [ "$add" = 1 ] && printf '\n'; } \
    | dd of="$live" bs=$(( len + add )) count=1 iflag=fullblock oflag=append conv=notrunc status=none 2>/dev/null \
    || { PG_WHY="append to $live failed"; return 1; }
  PG_REPLAYED=$(( len + add ))
  return 0
}

# pg_watch_tick <record> - one check of one watch record
pg_watch_tick() {
  local rec="$1" size i k pid st comm off state alive minoff=-1 open=0 rw app pos
  declare -A hp=()
  pg_watch_load "$rec" || { log_warn "watch: dropping unreadable record $rec"; rm -f "$rec"; return 0; }
  if [ ! -e "$PG_W_COPY" ]; then
    log_error "watch: $PG_W_COPY disappeared before its readers finished it (removed outside this tool)"
    rm -f "$rec"; return 0
  fi
  size=$(stat -c %s "$PG_W_COPY")
  # A writer that has not reopened yet (rsyslog handles its HUP a moment later) can still add lines to the
  # copy. While one does, "the reader reached the end" is not final: keep watching, and replay only after the
  # writer has let go, so the replay covers its last lines too.
  local wr=0
  while IFS='|' read -r pid comm k rw app pos; do
    [ -n "$pid" ] || continue
    if [ "$rw" != "r" ]; then wr=1; continue; fi
    if [ -z "${hp[$pid]:-}" ] || [ "$pos" -gt "${hp[$pid]}" ]; then hp[$pid]=$pos; fi
  done < <(DET_BY_INODE=1 det_proc_users "$PG_W_COPY")
  for i in "${!PG_W_ROWS[@]}"; do
    IFS='|' read -r k pid st comm off state <<<"${PG_W_ROWS[$i]}"
    if [ "$state" = "watching" ]; then
      alive=0; [ "$(pg_pid_start "$pid" 2>/dev/null)" = "$st" ] && alive=1
      if [ "$alive" = 1 ] && [ -n "${hp[$pid]:-}" ]; then
        [ "${hp[$pid]}" -gt "$off" ] && off=${hp[$pid]}
        [ "$off" -ge "$size" ] && [ "$wr" = 0 ] && state=done
      elif [ "$off" -ge "$size" ] && [ "$wr" = 0 ]; then
        state=done
      else
        state=abandoned
        log_warn "watch: reader $k ($comm, pid $pid) $([ "$alive" = 1 ] && echo "closed" || echo "exited") with $(human $(( size - off ))) of $PG_W_COPY unread - replaying it into $PG_W_LIVE"
      fi
      PG_W_ROWS[$i]="$k|$pid|$st|$comm|$off|$state"
    fi
    if [ "$state" = "abandoned" ] && { [ "$minoff" -lt 0 ] || [ "$off" -lt "$minoff" ]; }; then minoff=$off; fi
  done
  if [ "$minoff" -ge 0 ] && [ "$wr" = 0 ]; then     # replay once no writer adds to the copy any more
    PG_REPLAYED=0
    if pg_replay "$PG_W_COPY" "$PG_W_LIVE" "$minoff"; then
      log_success "watch: replayed $(human "$PG_REPLAYED") of unread data from $PG_W_COPY into $PG_W_LIVE"
      for i in "${!PG_W_ROWS[@]}"; do PG_W_ROWS[$i]="${PG_W_ROWS[$i]/%|abandoned/|replayed}"; done
      PG_SKIP_SEEN["$rec"]=""
    elif [ "${PG_SKIP_SEEN[$rec]:-}" != "$PG_WHY" ]; then
      PG_SKIP_SEEN["$rec"]="$PG_WHY"; log_error "watch: replay for $PG_W_COPY deferred - $PG_WHY"
    fi
  fi
  for i in "${!PG_W_ROWS[@]}"; do
    case "${PG_W_ROWS[$i]}" in *"|watching"|*"|abandoned") open=1;; esac
  done
  if [ "$open" = 1 ]; then
    pg_watch_save "$rec"
  else
    rm -f "$rec"; log_info "watch: every reader finished $PG_W_COPY"
  fi
  return 0
}

pg_watch_all() {
  local rec
  [ -d "$PG_WATCH_DIR" ] || return 0
  for rec in "$PG_WATCH_DIR"/*.watch; do [ -e "$rec" ] && pg_watch_tick "$rec"; done
  return 0
}

# ============================================================
# SECTION: Copy folder (where rotated copies are kept, and what they are named)
# ============================================================
# A rotated copy goes into a folder inside the log's own folder (setting PG_COPY_DIR, default "purged") and is
# named after the log and the time it will be deleted (setting PG_COPY_NAME), e.g.
#   /var/log/fw/purged/fw-01_delete-at_22-Nov-2026_at_03-29-37-PM-IST.log
# Its delete time is kept in a record (PG_COPIES_DIR, keyed by device+inode, which a rename keeps), so the name
# stays true even if the hold setting changes later. Without a record (records removed by hand) it is the
# copy's last-write time plus the hold. The folder is same-disk only (a move there must be a rename), must be
# a real folder owned by root (never a link), and is made again when it is missing. When it cannot be used the
# copy is kept beside the log as <file>.purge-<epoch>, so rotation goes on. Copies named <file>.purge-<epoch>
# (made by older versions, or with PG_COPY_DIR off) are still handled as before.

# pg_in_copy_dir <file> - 0 if the file sits directly in a copy folder (a real, root-owned folder) BELOW the
# path being processed. The configured folder itself is never a copy folder, even if it happens to be called
# "purged": its files are live logs.
pg_in_copy_dir() {
  [ "$PG_COPY_DIR" != off ] || return 1
  local d="${1%/*}" t="${TARGET_PATH:-}"
  t="${t%/}"
  [ -n "$t" ] && [[ "$d" == "$t/"* ]] || return 1
  [ "${d##*/}" = "$PG_COPY_DIR" ] && [ -d "$d" ] && [ ! -L "$d" ] && [ -O "$d" ]
}

# pg_copy_info <file> <hold-sec> - 0 if the file is one of our rotated copies; sets PG_COPY_DUE (delete time,
# epoch) and PG_COPY_REC (its record, "" if none)
# [<"dev ino mtime"> - already known (from find -printf): saves a stat per file in big folders]
pg_copy_info() {
  local f="$1" hold="$2" dev="" ino="" mt="" rec k v c="" due=""
  PG_COPY_DUE=""; PG_COPY_REC=""
  if [[ "${f##*/}" =~ \.purge-([0-9]+)$ ]]; then PG_COPY_DUE=$(( BASH_REMATCH[1] + hold )); return 0; fi
  if [ -n "${3:-}" ]; then read -r dev ino mt <<<"$3"; else read -r dev ino mt <<<"$(stat -c '%d %i %Y' -- "$f" 2>/dev/null)"; fi
  mt=${mt%.*}
  [ -n "$mt" ] || return 1
  rec="$PG_COPIES_DIR/$dev-$ino.copy"
  if [ -f "$rec" ]; then
    while IFS='=' read -r k v; do case "$k" in COPY) c=$v;; DELETE_AT) due=$v;; esac; done < "$rec"
    if [ "$c" = "$f" ] && [[ "$due" =~ ^[0-9]+$ ]]; then PG_COPY_DUE=$due; PG_COPY_REC=$rec; return 0; fi
  fi
  # Without a record only a file named like our copies counts: any other file that happens to sit in a
  # root-owned folder called "purged" (an application's own data, /opt/app/data/purged/db.bak) is not ours.
  if pg_in_copy_dir "$f" && pg_copy_name_like "${f##*/}"; then PG_COPY_DUE=$(( mt + hold )); return 0; fi
  return 1
}

# pg_copy_name_like <name> - 0 if the name has the shape of PG_COPY_NAME (any log name, any date), e.g.
# *_delete-at_*-*-*_at_*-*-*-*-** for the default
PG_CN_SRC=""; PG_CN_GLOB=""
pg_copy_name_like() {
  if [ "$PG_CN_SRC" != "$PG_COPY_NAME" ] || [ -z "$PG_CN_GLOB" ]; then
    # {name}, {ext} and every date code (%d, %-d, %_H ...) -> *, the rest literal (glob characters escaped)
    PG_CN_GLOB=$(printf '%s' "$PG_COPY_NAME" | sed -E 's/\{name\}|\{ext\}/\x02/g; s/%%/\x01/g; s/%[-_0^#]*[0-9]*[A-Za-z]/\x02/g; s/[][?*\\]/\\&/g; s/\x01/%/g; s/\x02+/*/g')
    PG_CN_SRC=$PG_COPY_NAME
  fi
  # shellcheck disable=SC2053
  [[ "$1" == $PG_CN_GLOB ]]
}

# pg_copy_dir_ready <folder> <live file> - 0 if copies of that file can go into the folder (made if missing).
# Sets PG_WHY when not.
pg_copy_dir_ready() {
  local d="$1" f="$2" p="${2%/*}" fd dd
  if [ -L "$d" ]; then PG_WHY="$d is a link, not a folder (a link could lead outside the log folder)"; return 1; fi
  if [ -e "$d" ] && [ ! -d "$d" ]; then PG_WHY="$d is a file, not a folder"; return 1; fi
  if [ ! -d "$d" ]; then
    if ! mkdir -m 0750 -- "$d" 2>/dev/null; then
      { [ -d "$d" ] && [ ! -L "$d" ]; } || { PG_WHY="could not create the folder $d"; return 1; }
    fi
    chgrp --reference="$p" -- "$d" 2>/dev/null
    if [ -d "$PG_COPIES_DIR" ] && grep -qsF -- "COPY=$d/" "$PG_COPIES_DIR"/*.copy 2>/dev/null; then
      log_warn "copy folder $d was missing (removed by hand?) - created it again"
    else
      log_info "created copy folder $d"
    fi
  fi
  [ -O "$d" ] || { PG_WHY="$d is not owned by root"; return 1; }
  read -r dd fd <<<"$(stat -c %d -- "$d" "$f" 2>/dev/null | tr '\n' ' ')"
  [ -n "$fd" ] && [ "$dd" = "$fd" ] || { PG_WHY="$d is on another disk (a move there would copy the file, not rename it)"; return 1; }
  return 0
}

# pg_copy_dest <live file> <delete-at epoch> - sets PG_DEST (where the copy goes) and PG_DEST_DIR (its copy
# folder; "" = kept beside the log under the old <file>.purge-<epoch> name)
pg_copy_dest() {
  local f="$1" due="$2" d base name ext nm
  PG_DEST="${f}.purge-$(date +%s)"; PG_DEST_DIR=""
  [ "$PG_COPY_DIR" != off ] || return 0
  case "$f" in *$'\n'*) return 0;; esac
  d="${f%/*}/$PG_COPY_DIR"
  if ! pg_copy_dir_ready "$d" "$f"; then
    if [ "${PG_SKIP_SEEN[copydir:$d]:-}" != "$PG_WHY" ]; then
      PG_SKIP_SEEN["copydir:$d"]="$PG_WHY"
      log_warn "copy folder not used: $PG_WHY - copies of logs in ${f%/*} are kept beside them (<file>.purge-<time>) until it is fixed"
    fi
    return 0
  fi
  PG_SKIP_SEEN["copydir:$d"]=""
  base="${f##*/}"
  if [[ "$base" == ?*.* ]]; then ext=".${base##*.}"; name="${base%.*}"; else ext=""; name="$base"; fi
  nm=$(LC_ALL=C date -d "@$due" +"$PG_COPY_NAME" 2>/dev/null)
  nm=${nm//\{name\}/"$name"}; nm=${nm//\{ext\}/"$ext"}
  if [ -z "$nm" ] || [[ "$nm" == */* ]] || [ "${#nm}" -gt 250 ] || [ "$nm" = . ] || [ "$nm" = .. ] || [[ "$nm" =~ \.purge-[0-9]+$ ]]; then
    if [ "${PG_SKIP_SEEN[copyname:$f]:-}" != 1 ]; then
      PG_SKIP_SEEN["copyname:$f"]=1; log_warn "the copy name from PG_COPY_NAME cannot be used for $base (empty, too long or contains /) - kept as <file>.purge-<time>"
    fi
    return 0
  fi
  PG_DEST="$d/$nm"; PG_DEST_DIR="$d"
}

# pg_copy_record <copy> <live> <delete-at> <dev-ino of the live file> - written BEFORE the move (like the watch
# record), so a crash between the move and the bookkeeping never leaves a copy without its delete time
pg_copy_record() {
  local rec="$PG_COPIES_DIR/$4.copy" tmp
  mkdir -p "$PG_COPIES_DIR" 2>/dev/null && chmod 700 "$PG_COPIES_DIR" 2>/dev/null || return 1
  tmp="$rec.tmp.$$"
  printf 'COPY=%s\nLIVE=%s\nPATH=%s\nDELETE_AT=%s\n' "$1" "$2" "${TARGET_PATH:-}/${PATTERN:-}" "$3" > "$tmp" && mv -f "$tmp" "$rec"
}

# pg_move_copy <live> <dest> - the rename. If the copy folder was removed at this very moment, make it again
# and try once more; on failure the live file is untouched.
pg_move_copy() {
  # checked again right before the move: removed meanwhile -> made again; turned into a link or a file -> refused
  if [ -n "$PG_DEST_DIR" ] && { [ -L "$PG_DEST_DIR" ] || [ ! -d "$PG_DEST_DIR" ]; }; then
    pg_copy_dir_ready "$PG_DEST_DIR" "$1" && [ ! -e "$2" ] || return 1
  fi
  mv -T -- "$1" "$2" 2>/dev/null && return 0
  # removed in the instant between that check and the move: once more
  [ -n "$PG_DEST_DIR" ] && [ ! -e "$PG_DEST_DIR" ] || return 1
  pg_copy_dir_ready "$PG_DEST_DIR" "$1" && [ ! -e "$2" ] && mv -T -- "$1" "$2" 2>/dev/null
}

# pg_copies_sweep - forget copies that were removed outside this tool (logged once, when noticed)
pg_copies_sweep() {
  local rec k v c d
  declare -A gone=()
  [ -d "$PG_COPIES_DIR" ] || return 0
  for rec in "$PG_COPIES_DIR"/*.copy; do
    [ -f "$rec" ] || continue
    c=""; while IFS='=' read -r k v; do [ "$k" = COPY ] && c=$v; done < "$rec"
    if [ -z "$c" ] || [ ! -e "$c" ]; then
      if [ -n "$c" ]; then
        d="${c%/*}"
        if [ -e "$d" ]; then log_warn "copy $c is gone - removed outside this tool (by hand?); forgotten"
        else gone[$d]=$(( ${gone[$d]:-0} + 1 )); fi
      fi
      rm -f "$rec"
    fi
  done
  for d in "${!gone[@]}"; do
    log_warn "copy folder $d was removed outside this tool (by hand?) with ${gone[$d]} copies in it - forgotten; it is made again at the next rotation"
  done
  return 0
}

# pg_when <epoch> - a delete time for messages, in the server's time zone (22 Nov 2026 03:29:37 PM IST)
pg_when() { LC_ALL=C date -d "@$1" '+%d %b %Y %I:%M:%S %p %Z' 2>/dev/null; }

# pg_path_files <target> <pattern> <hold-sec> - NUL-separated: the path's files (live, finished, date-named),
# then its rotated copies, oldest delete time first. Copy folders are not searched for live files.
# One find per folder and no command per file (a big folder such as /opt holds many thousands of files).
pg_path_files() {
  local t="$1" p="$2" hold="$3" full="$1/$2" file d k v pth dev ino mt r
  local -a files=() copies=() prune=()
  declare -A recs=()
  for r in "$PG_COPIES_DIR"/*.copy; do [ -f "$r" ] && { r=${r##*/}; recs[${r%.copy}]=1; }; done
  [ "$PG_COPY_DIR" != off ] && prune=( -mindepth 1 \( -type d -name "$PG_COPY_DIR" -prune \) -o )
  while IFS=$'\t' read -r -d '' dev ino mt file; do
    [ -n "$file" ] || continue
    # only an old .purge-<epoch> name or a file with a copy record can be a copy here (copy folders are pruned)
    if { [[ "$file" == *.purge-* ]] || [ -n "${recs[$dev-$ino]:-}" ]; } && pg_copy_info "$file" "$hold" "$dev $ino $mt"; then
      copies+=("$PG_COPY_DUE"$'\t'"$file")
    else
      files+=("$file")
    fi
  done < <(find "$t" ${prune[@]+"${prune[@]}"} -type f \( -name "$p" -o -name "${p}.purge-*" \) -printf '%D\t%i\t%T@\t%p\0' 2>/dev/null)
  if [ "$PG_COPY_DIR" != off ]; then
    declare -A others=()
    while IFS= read -r r; do [ -n "$r" ] && [ "$r" != "$full" ] && others[$r]=1; done < <(awk '
      FNR == 1 && NR > 1 { print t "/" p }
      /^TARGET_PATH=/ { t = substr($0, 13); gsub(/"/, "", t) }
      /^PATTERN=/     { p = substr($0, 9);  gsub(/"/, "", p) }
      END { if (NR) print t "/" p }' "$PATHS_DIR"/*.conf 2>/dev/null)
    while IFS= read -r -d '' d; do
      while IFS=$'\t' read -r -d '' dev ino mt file; do
        [ -n "$file" ] || continue
        pg_copy_info "$file" "$hold" "$dev $ino $mt" || continue
        # this path's copy unless its record names ANOTHER configured path (two paths in one folder share its
        # copy folder). Without a record (removed by hand), or with one from before the path was edited, the
        # folder decides: it is below this path.
        if [ -n "$PG_COPY_REC" ] && [ "${#others[@]}" -gt 0 ]; then
          pth=""; while IFS='=' read -r k v; do [ "$k" = PATH ] && pth=$v; done < "$PG_COPY_REC"
          [ -n "$pth" ] && [ -n "${others[$pth]:-}" ] && continue
        fi
        copies+=("$PG_COPY_DUE"$'\t'"$file")
      done < <(find "$d" -mindepth 1 -maxdepth 1 -type f -printf '%D\t%i\t%T@\t%p\0' 2>/dev/null)
    done < <(find "$t" -mindepth 1 -type d -name "$PG_COPY_DIR" -prune -print0 2>/dev/null)
  fi
  [ "${#files[@]}" -gt 0 ] && printf '%s\0' "${files[@]}"
  [ "${#copies[@]}" -gt 0 ] && printf '%s\0' "${copies[@]}" | sort -z -n -t $'\t' -k1,1 | cut -z -f2-
  return 0
}

# pg_do_rotate <file> - rename aside, recreate with the same mode/owner, reload writers, verify.
# rc: 0 done | 2 deferred (retry later) | 1 failed
pg_do_rotate() {
  local f="$1" mode uid gid dest c t=0 held=1 reatt=0 rk rkinds snap
  if ! pg_wait_caught_up "$f"; then
    # Not at EOF. Every reader that holds the file keeps draining the renamed copy, and the watch
    # record covers one that crashes mid-way. Never when a reader is down/unknown (it does not hold
    # the copy, so it could not drain it), has not noticed a shrink yet, or is too far behind to replay.
    if [ "$PG_ALLOW_BEHIND" != "1" ]; then return 2; fi
    if [ -n "$PG_BLOCK" ] || [ "$PG_STALE" = "1" ] || [ "$PG_UNREAD_STORED" -gt 0 ] || ! pg_readers_drain "$1"; then return 2; fi
    if [ "$PG_UNREAD" -gt "$PG_MAX_BEHIND" ]; then
      PG_WHY="readers $(human "$PG_UNREAD") behind - more than PG_MAX_BEHIND ($(human "$PG_MAX_BEHIND")); waiting for them"; return 2
    fi
    log_info "rotating $f with readers $(human "$PG_UNREAD") behind: they drain the old copy, a crash is replayed"
  fi
  pg_writers_check "$f"
  rkinds=$(det_proc_users "$f" | awk -F'|' '$4=="r" {print $3}' | sort -u | tr '\n' ' ')
  local due key crec=""
  read -r mode uid gid key <<<"$(stat -c '%a %u %g %d-%i' "$f")"
  due=$(( $(date +%s) + ${HOLD_SEC:-$PG_GRACE_SEC} ))
  pg_copy_dest "$f" "$due"; dest=$PG_DEST
  if [ -e "$dest" ]; then PG_WHY="rotation target already exists: $dest"; return 2; fi
  snap=$(pg_readers_snapshot "$f")
  if ! pg_watch_create "$dest" "$f" "$snap"; then PG_WHY="cannot write watch record in $PG_WATCH_DIR - not rotating"; return 2; fi
  if [ -n "$PG_DEST_DIR" ]; then
    crec="$PG_COPIES_DIR/$key.copy"
    pg_copy_record "$dest" "$f" "$due" "$key" || { rm -f "$(pg_watch_rec "$dest")"; PG_WHY="cannot write copy record in $PG_COPIES_DIR - not rotating"; return 2; }
  fi
  # From the move to the reload nothing may be cut short. A service stop or restart (systemd sends TERM to
  # every process of the service) used to kill the reload command right after the move, leaving the writer
  # on the moved copy and no live file. These steps run with TERM ignored; the stop is acted on after them.
  pg_noterm pg_move_copy "$f" "$dest" || { rm -f "$(pg_watch_rec "$dest")" ${crec:+"$crec"}; PG_WHY="could not move $f to $dest"; return 1; }
  # recreate immediately so the file never stays missing, keeping its original permissions
  pg_noterm pg_recreate "$f" "$mode" "$uid" "$gid"
  for c in ${PG_RELOAD_CMDS[@]+"${PG_RELOAD_CMDS[@]}"}; do
    pg_noterm $c >/dev/null 2>&1 || log_warn "reload command failed: $c"
  done
  # t counts 0.2s steps. Readers often finish the old copy within a second of the rotation, so its
  # watch record is sampled at this finer step here (fewer lines replayed twice when one closes fast).
  while [ "$t" -lt $(( PG_VERIFY_SEC * 5 )) ]; do
    pg_watch_open "$dest" && pg_watch_tick "$(pg_watch_rec "$dest")"
    held=$(det_proc_users "$dest" | awk -F'|' '$4!="r"' | wc -l)
    reatt=0
    for rk in $rkinds; do
      det_proc_users "$f" | awk -F'|' -v k="$rk" '$3==k && $4=="r" {ok=1} END {exit !ok}' || reatt=1
    done
    [ "$held" -eq 0 ] && [ "$reatt" -eq 0 ] && break
    sleep 0.2; t=$(( t + 1 ))
  done
  if [ "$held" -gt 0 ]; then
    # a writer is still appending to the renamed file: put things back if nothing new landed and nobody has
    # opened the new file yet (replacing a file another process already writes would leave it writing into
    # a deleted file)
    if [ ! -s "$f" ] && [ -z "$(det_proc_users "$f")" ]; then
      mv -f -T -- "$dest" "$f" && rm -f "$(pg_watch_rec "$dest")" ${crec:+"$crec"} && PG_WHY="writer did not reopen after reload - rotation rolled back"
    else PG_WHY="writer still on $dest after reload while the new file is already in use - left in place"; fi
    log_error "$PG_WHY ($f)"
    return 1
  fi
  [ "$reatt" -ne 0 ] && log_warn "reader(s) [${rkinds% }] did not re-attach to $f within ${PG_VERIFY_SEC}s - they will finish the old copy first"
  log_success "rotated $f -> $dest (reload: ${PG_RELOAD_CMDS[*]:-none needed}; readers: ${rkinds:-none})"
  return 0
}

# pg_do_truncate <file> - fallback. Waits for readers, optionally copies aside, truncates.
# rc: 0 done | 2 deferred | 1 failed
pg_do_truncate() {
  local f="$1" sz free d
  pg_wait_caught_up "$f" || return 2
  sz=$(stat -c %s "$f" 2>/dev/null || echo 0)
  mkdir -p "$PG_ASIDE_DIR" 2>/dev/null && chmod 700 "$PG_ASIDE_DIR" 2>/dev/null
  free=$(df --output=avail -B1 "$PG_ASIDE_DIR" 2>/dev/null | tail -1 | tr -dc '0-9')
  if [ "${free:-0}" -gt $(( sz + PG_ASIDE_MARGIN )) ]; then
    d="$PG_ASIDE_DIR/$(path_id "$f")"; mkdir -p "$d" && chmod 700 "$PG_ASIDE_DIR" "$d" 2>/dev/null
    cp -- "$f" "$d/${f##*/}.$(date +%s)" 2>/dev/null || log_warn "aside copy failed for $f (continuing)"
  else
    log_warn "not enough free space for an aside copy of $f - truncating without one"
  fi
  if truncate -s 0 "$f" 2>/dev/null; then
    log_success "truncated $f in place ($(human "$sz")) - writers append-mode, readers were at EOF"
    return 0
  fi
  PG_WHY="truncate failed (check chattr/permissions)"; log_error "$PG_WHY: $f"; return 1
}

# pg_clean_aside - drop aside copies older than PG_ASIDE_KEEP_SEC
pg_clean_aside() {
  [ -d "$PG_ASIDE_DIR" ] || return 0
  find "$PG_ASIDE_DIR" -type f -mmin +$(( PG_ASIDE_KEEP_SEC / 60 )) -delete 2>/dev/null
}

# pg_process_file <file> <due 0|1> <dry 0|1> <verbose> <force>
# Sets PG_FREED (bytes reclaimed right now), PG_OUTCOME (acted|skipped|deferred|idle),
# PG_LIVE (""|acted|pending - whether a live file was handled or must be retried).
pg_process_file() {
  local f="$1" due="$2" dry="$3" verbose="$4" force="$5"
  local sz base now mins age action rc why nlinks old=0 hold="${HOLD_SEC:-$PG_GRACE_SEC}"
  PG_FREED=0; PG_OUTCOME="idle"; PG_LIVE=""
  local cdue="" crec="" sdev="" sino="" smt=""
  read -r sz sdev sino smt <<<"$(stat -c '%s %d %i %Y' -- "$f" 2>/dev/null)"
  sz=${sz:-0}; base="${f##*/}"; now=$(date +%s)
  mins=$(unit_to_min "$RETENTION_VALUE" "$RETENTION_UNIT")
  if [ -n "$smt" ] && pg_copy_info "$f" "$hold" "$sdev $sino $smt"; then old=1; cdue=$PG_COPY_DUE; crec=$PG_COPY_REC; else pg_old_name "$base" && old=1; fi
  # A name that looks finished can still be the live file a writer is on right now:
  #  - size / daily mode: a date-named file (firewall_20261120.log, fw-20261124) is today's file - without this
  #    it was never rotated and its size limit never applied (in time mode it is finished once its day is over)
  #  - any mode: a name ending in .<digits> that is no date, e.g. 192.168.1.10 (rsyslog's one-file-per-sender
  #    template %FROMHOST-IP%) - it was taken for a rotated app.log.1 and never rotated, so it grew forever
  # It counts as live only while a writer has it open, or rsyslog's config writes it. For a .<digits> name a
  # wildcard rsyslog template (/var/log/%programname% -> /var/log/*) would also match logrotate's syslog.1, so
  # there it must also have been written in the last PG_RECENT_WRITE_SEC. Compressed, .old/.sum names and
  # .purge- copies are always finished.
  if [ "$old" = 1 ] && [ -z "$cdue" ] && ! [[ "$base" =~ \.(gz|xz|bz2|zst|old|sum)$|\.purge-[0-9]+$ ]]; then
    local maybe_live=0
    if pg_dated_name "$base"; then
      if [ "$RETENTION_UNIT" = "mb" ] || [ "$RETENTION_UNIT" = "midnight" ]; then maybe_live=1; fi
    elif [[ "$base" =~ \.[0-9]+$ ]]; then
      maybe_live=2
    fi
    if [ "$maybe_live" != 0 ]; then
      pg_writers_check "$f"
      if [ "$PG_WRITERS" -gt 0 ] && { [ "$maybe_live" = 1 ] || [ -z "$PG_WRITER_CONF" ] || [ "${DET_RS_HOW:-}" = exact ] \
           || [ $(( now - ${smt:-0} )) -lt "$PG_RECENT_WRITE_SEC" ]; }; then old=0; fi
    fi
  fi
  if [ "$force" != "force" ] && [ "${PG_NEXT_TRY[$f]:-0}" -gt "$now" ]; then
    PG_OUTCOME="skipped"
    [ "$old" = 1 ] || PG_LIVE="pending"    # a backed-off live file is still unhandled
    return 0
  fi
  if why=$(pg_protected_file "$f"); then
    PG_OUTCOME="protected"; [ -n "$verbose" ] && [ "$dry" = "1" ] && pg_say "$C_DIM" "$f" "never touched: $why"
    return 0
  fi
  if pg_in_quiet_window "$f"; then
    PG_OUTCOME="deferred"; [ "$old" = 1 ] || PG_LIVE="pending"
    [ -n "$verbose" ] && pg_say "$C_YELLOW" "$f" "waiting: Wazuh rotates its logs at midnight (no action 23:55-00:10)"
    return 0
  fi

  # ---- rotated / date-named / old file ---------------------------------------
  if [ "$old" = 1 ]; then
    if [ -n "$cdue" ]; then
      if [ "$now" -lt "$cdue" ]; then
        # Held copy, until its delete time. Early removal only to stop the disk filling up (a full disk makes
        # writers drop new logs) - and even then only once every reader has finished it (checked below).
        local use; use=$(df --output=pcent "$f" 2>/dev/null | tail -1 | tr -dc '0-9')
        [ "${use:-0}" -ge "$PG_DISK_EMERGENCY_PCT" ] || return 0
        [ "$dry" = "1" ] || log_warn "disk at ${use}% (>= ${PG_DISK_EMERGENCY_PCT}%): releasing fully-read copy $f before its delete time ($(pg_when "$cdue"))"
      fi
      if pg_watch_open "$f"; then pg_skip "$f" "a reader has not finished this copy yet (watch record open)"; PG_OUTCOME="deferred"; return 0; fi
    else
      case "$RETENTION_UNIT" in hours|days|weeks|months) ;; *) return 0;; esac    # size/midnight modes leave foreign rotated files alone
      age=$(( now - $(stat -c %Y "$f" 2>/dev/null || echo "$now") ))
      [ "$age" -ge $(( mins * 60 )) ] || return 0
    fi
    local kind="rotated file"
    if [ -n "$cdue" ]; then kind="rotated copy"; elif ! pg_rotated_name "$base"; then kind="date-named file"; fi
    if ! pg_finished_file_check "$f"; then
      pg_skip "$f" "$kind kept: $PG_WHY"; PG_OUTCOME="deferred"
      [ -n "$verbose" ] && [ "$dry" = "1" ] && pg_say "$C_DIM" "$f" "kept: $PG_WHY"
      return 0
    fi
    nlinks=$(stat -c %h "$f" 2>/dev/null || echo 1)
    if [ "$dry" = "1" ]; then
      [ "$nlinks" -le 1 ] && PG_FREED=$sz; PG_OUTCOME="acted"
      [ -n "$verbose" ] && pg_say "$C_YELLOW" "$f" "${C_DIM}dry-run: would delete $kind ($(human "$sz"), $(( (now - $(stat -c %Y "$f")) / 3600 ))h old; readers finished)${C_RESET}"; return 0
    fi
    # last check right before deleting: nothing may have changed in the meantime
    if ! pg_finished_file_check "$f"; then pg_skip "$f" "$kind kept: $PG_WHY"; PG_OUTCOME="deferred"; return 0; fi
    if rm -f -- "$f"; then
      # removing one name of a hard-linked file releases no space until the last name goes
      [ "$nlinks" -le 1 ] && PG_FREED=$sz
      PG_OUTCOME="acted"; PG_SKIP_SEEN["$f"]=""
      [ -n "$crec" ] && rm -f "$crec"
      log_info "deleted $kind $f ($(human "$sz"))"
      [ -n "$verbose" ] && pg_say "$C_GREEN" "$f" "deleted $kind ($(human "$sz"))"
    else
      pg_skip "$f" "could not delete (check permissions/chattr)"; PG_OUTCOME="skipped"
    fi
    return 0
  fi

  # ---- live file -----------------------------------------------------------
  [ "$sz" -gt 0 ] && [ "$due" = "1" ] || return 0
  nlinks=$(stat -c %h "$f" 2>/dev/null || echo 1)
  pg_consumers_check "$f"
  if [ -n "$PG_BLOCK" ]; then pg_skip "$f" "$PG_BLOCK"; PG_OUTCOME="deferred"; PG_LIVE="pending"; return 0; fi
  pg_writers_check "$f"
  if [ "$PG_WRITERS" -eq 0 ]; then
    # Holds nobody (and no rsyslog config names it - pg_writers_check), but written within the last
    # PG_RECENT_WRITE_SEC: its writer may have just been told to reopen. Wait for it to come back first.
    local mt w=0; mt=$(stat -c %Y "$f" 2>/dev/null || echo 0)
    if [ $(( now - mt )) -lt "$PG_RECENT_WRITE_SEC" ]; then
      while [ "$w" -lt "$PG_VERIFY_SEC" ] && [ "$PG_WRITERS" -eq 0 ]; do sleep 1; w=$(( w + 1 )); pg_writers_check "$f"; done
      if [ "$PG_WRITERS" -eq 0 ]; then
        case "$RETENTION_UNIT" in
          hours|days|weeks|months)
            # a writer that opens the file for every write and closes it again: time mode waits for it to go quiet
            pg_skip "$f" "it is being written, but no process keeps it open (a writer that opens it for each write) - a time-based path waits until it has been unwritten for ${RETENTION_VALUE} ${RETENTION_UNIT}; use size (e.g. 500mb) or midnight mode for such a file"
            PG_OUTCOME="deferred"; PG_LIVE="acted"; return 0;;
        esac
      else
        pg_consumers_check "$f"                     # the writer is back: take a fresh look at the readers too
        if [ -n "$PG_BLOCK" ]; then pg_skip "$f" "$PG_BLOCK"; PG_OUTCOME="deferred"; PG_LIVE="pending"; return 0; fi
      fi
    fi
  fi
  if   [ "$PG_WRITERS" -eq 0 ];      then
    # Nobody is writing it. Time-based retention: once it is older than the retention, set it aside as
    # <file>.purge-<epoch> (no empty stand-in is created) - held like any rotated copy, then deleted.
    # Size / midnight modes keep the path: rotate it, which leaves an empty file in its place.
    case "$RETENTION_UNIT" in
      hours|days|weeks|months)
        age=$(( now - $(stat -c %Y "$f" 2>/dev/null || echo "$now") ))
        if [ "$age" -lt $(( mins * 60 )) ]; then
          # not silent: say once why a non-empty file that was due is left as it is
          if [ "$dry" != "1" ] && [ -z "${PG_PLAN_QUIET:-}" ] && [ "${PG_SKIP_SEEN[idle:$f]:-}" != 1 ]; then
            PG_SKIP_SEEN["idle:$f"]=1
            log_info "not rotated: $f - no process has it open and no rsyslog config writes it, so it counts as finished; it is set aside once unwritten for ${RETENTION_VALUE} ${RETENTION_UNIT}"
          fi
          PG_OUTCOME="idle"; PG_LIVE="acted"; return 0
        fi
        if [ "$PG_UNREAD" -gt 0 ]; then pg_skip "$f" "readers have not finished it ($(human "$PG_UNREAD") unread)"; PG_OUTCOME="deferred"; PG_LIVE="pending"; return 0; fi
        action="retire";;
      *) action="rotate";;
    esac
  elif [ "$PG_UNRELOADABLE" -eq 0 ]; then action="rotate"
  elif [ "$PG_ALL_APPEND" -eq 1 ];   then
    why=$(pg_truncate_blockers "$f")
    if [ -n "$why" ]; then
      pg_skip "$f" "writer cannot be reloaded, so rotation is impossible, and truncation is unsafe: $why"
      PG_OUTCOME="skipped"; PG_LIVE="acted"; return 0
    fi
    action="truncate"
  else
    pg_skip "$f" "writer is not in append mode and cannot be reloaded - touching it would corrupt the file"
    PG_OUTCOME="skipped"; PG_LIVE="acted"; return 0
  fi
  if [ "$action" = "rotate" ] && [ "$nlinks" -gt 1 ]; then
    # Hard-linked (e.g. Wazuh archives.json == archives/YYYY/Mon/ossec-archive-DD.json): renaming one name
    # frees no space and splits it from the writer. Only an in-place truncate is correct, and only if safe.
    why=$(pg_truncate_blockers "$f")
    if [ "$PG_ALL_APPEND" -eq 1 ] && [ -z "$why" ]; then action="truncate"
    else
      pg_skip "$f" "file has $nlinks hard links, so it cannot be rotated, and truncating is unsafe: ${why:-writer is not in append mode}"
      PG_OUTCOME="skipped"; PG_LIVE="acted"; return 0
    fi
  fi
  if [ "$action" = "truncate" ] && [ "${PATH_ALLOW_TRUNCATE:-$PG_ALLOW_TRUNCATE}" != "1" ]; then
    # Truncating in place has a small window in which a reader can miss lines. Off unless turned on.
    pg_skip "$f" "this file could only be emptied in place (writer cannot be reloaded$([ "$nlinks" -gt 1 ] && echo ", or it has $nlinks hard links")), and emptying in place is off for this path (setting PG_ALLOW_TRUNCATE / path option) - left untouched"
    PG_OUTCOME="skipped"; PG_LIVE="acted"; return 0
  fi
  if [ "$dry" = "1" ]; then
    PG_OUTCOME="acted"; PG_LIVE="acted"; { [ "$action" = "truncate" ] || { [ "$action" = "delete" ] && [ "$nlinks" -le 1 ]; }; } && PG_FREED=$sz
    [ -n "$verbose" ] && pg_say "$C_YELLOW" "$f" "${C_DIM}dry-run: would ${action} ($(human "$sz"); readers $(human "$PG_UNREAD") behind; writers=${PG_WRITERS})${C_RESET}"
    return 0
  fi
  case "$action" in
    rotate) pg_do_rotate "$f"; rc=$?;;
    retire)
      local rdest rsnap rdue=$(( now + hold )) rkey rrec=""
      rkey=$(stat -c '%d-%i' -- "$f" 2>/dev/null)
      pg_copy_dest "$f" "$rdue"; rdest=$PG_DEST
      [ -n "$PG_DEST_DIR" ] && rrec="$PG_COPIES_DIR/$rkey.copy"
      rsnap=$(pg_readers_snapshot "$f")
      if [ -e "$rdest" ]; then rc=2; PG_WHY="target already exists: $rdest"
      elif ! pg_watch_create "$rdest" "$f" "$rsnap"; then rc=2; PG_WHY="cannot write watch record in $PG_WATCH_DIR"
      elif [ -n "$rrec" ] && ! pg_copy_record "$rdest" "$f" "$rdue" "$rkey"; then
        rm -f "$(pg_watch_rec "$rdest")"; rc=2; PG_WHY="cannot write copy record in $PG_COPIES_DIR"
      elif pg_move_copy "$f" "$rdest"; then rc=0; log_info "set aside stale file $f -> $rdest ($(human "$sz"), unwritten for ${age}s; deleted at $(pg_when "$rdue"))"
      else rm -f "$(pg_watch_rec "$rdest")" ${rrec:+"$rrec"}; rc=1; PG_WHY="could not move it to $rdest (check permissions/chattr)"; fi;;
    *)      pg_do_truncate "$f"; rc=$?;;
  esac
  case "$rc" in
    0) PG_OUTCOME="acted"; PG_LIVE="acted"; PG_SKIP_SEEN["$f"]=""; PG_SKIP_SEEN["idle:$f"]=""; unset "PG_NEXT_TRY[$f]" 2>/dev/null
       { [ "$action" = "truncate" ] || { [ "$action" = "delete" ] && [ "$nlinks" -le 1 ]; }; } && PG_FREED=$sz
       [ -n "$verbose" ] && pg_say "$C_GREEN" "$f" "${action}d ($(human "$sz"))";;
    2) pg_skip "$f" "$PG_WHY"; PG_OUTCOME="deferred"; PG_LIVE="pending";;
    *) pg_skip "$f" "$PG_WHY"; PG_OUTCOME="skipped"; PG_LIVE="pending";;
  esac
  return 0
}

# purge_one_path <conf_file> <verbose> <force> <dry_run>
# Processes a single configured path independently - a failure here never
# aborts processing of the remaining configured paths.
purge_one_path() {
  local f="$1" verbose="$2" force="$3" dry="$4" why
  load_conf "$f" || { log_error "skip (corrupted config): $f"; return 1; }
  [ "$ENABLED" = "1" ] || return 0
  # checked again on every pass: an older or hand-edited conf, or a protection added in the settings later
  if ! why=$(safe_target "$TARGET_PATH"); then
    if [ "${PG_SKIP_SEEN[unsafe:$f]:-}" != "$why" ]; then PG_SKIP_SEEN["unsafe:$f"]="$why"; log_error "skip $TARGET_PATH (not managed): $why"; fi
    return 0
  fi
  if [ ! -d "$TARGET_PATH" ]; then
    if [ -z "${PG_SKIP_SEEN[missing:$TARGET_PATH]:-}" ]; then
      PG_SKIP_SEEN["missing:$TARGET_PATH"]=1; log_warn "skip (folder does not exist; reported once): $TARGET_PATH"
    fi
    return 0
  fi
  det_cache_refresh
  if [ "$dry" = "1" ] && [ -n "$verbose" ]; then
    printf "%s%s%s  (pattern %s, keep %s%s, hold %s)\n" "$C_BOLD" "$TARGET_PATH" "$C_RESET" "$PATTERN" "$RETENTION_VALUE" "$RETENTION_UNIT" "$(human_secs "${HOLD_SEC:-$PG_GRACE_SEC}")"
    det_conflicts_report "$TARGET_PATH" "$PATTERN" | sed 's/^/  /'
  fi

  local mins id freed=0 live_acted=0 live_pending=0 acted=0 due=0 file sz file_due threshold_bytes=0 ino
  declare -A seen_ino=()
  local now_epoch last_purge_epoch new_lp
  mins=$(unit_to_min "$RETENTION_VALUE" "$RETENTION_UNIT")
  id=$(path_id "${TARGET_PATH}/${PATTERN}")
  now_epoch=$(date +%s); last_purge_epoch=${LAST_PURGE:-0}

  # Live files that were due but had to be deferred (a reader behind, a writer that did not reopen ...) are
  # remembered one by one and retried every pass until handled. The path's interval restarts on schedule, so
  # one stuck file can no longer make every other file in the folder rotate on every pass.
  declare -A pend=() pend_new=()
  local pend_file="$PG_PENDING_DIR/$id.list" pl
  if [ "$RETENTION_UNIT" != "mb" ] && [ -r "$pend_file" ]; then
    while IFS= read -r -d '' pl; do [ -n "$pl" ] && pend[$pl]=1; done < "$pend_file"
  fi

  if [ "$RETENTION_UNIT" = "mb" ]; then
    threshold_bytes=$(( RETENTION_VALUE * 1024 * 1024 ))
  elif [ "$RETENTION_UNIT" = "midnight" ]; then
    # daily mode: due once the most recent daily rotation time (setting PG_DAILY_AT) has passed since the last run
    local boundary noon
    boundary=$(date -d "$(date +%F) ${PG_DAILY_AT:0:2}:${PG_DAILY_AT:2:2}" +%s 2>/dev/null)
    if [ -z "$boundary" ]; then
      # that time does not exist today (skipped by a daylight-saving change): count from noon instead of
      # falling back to "now", which made the path due on every pass for the whole day
      noon=$(date -d "$(date +%F) 12:00" +%s)
      boundary=$(( noon - 43200 + 10#${PG_DAILY_AT:0:2} * 3600 + 10#${PG_DAILY_AT:2:2} * 60 ))
    fi
    [ "$now_epoch" -lt "$boundary" ] && boundary=$(( boundary - 86400 ))
    [ "$last_purge_epoch" -lt "$boundary" ] && due=1
  else
    [ $(( now_epoch - last_purge_epoch )) -ge $(( mins * 60 )) ] && due=1
  fi
  [ "$force" = "force" ] && due=1

  # Our rotated copies are visited oldest first (by the time in their name), after the other files.
  # Below the disk limit the order does not matter. At the limit a held copy is released only while the
  # disk is still at the limit (re-checked per copy), so this order frees the oldest hours and keeps the
  # newest ones in one unbroken run - folder order released random hours and left gaps.
  local -a pg_files=()
  while IFS= read -r -d '' file; do pg_files+=("$file"); done \
    < <(pg_path_files "$TARGET_PATH" "$PATTERN" "${HOLD_SEC:-$PG_GRACE_SEC}")

  for file in ${pg_files[@]+"${pg_files[@]}"}; do
    [ -L "$file" ] && { log_warn "skip (symlink): $file"; continue; }
    if ! pg_old_name "${file##*/}"; then
      # several names for one live file (hard links) must be processed once, not once per name
      ino=$(stat -c '%d:%i' "$file" 2>/dev/null)
      [ -n "$ino" ] && [ -n "${seen_ino[$ino]:-}" ] && continue
      [ -n "$ino" ] && seen_ino[$ino]=1
    fi
    file_due=$due
    if [ "$RETENTION_UNIT" = "mb" ]; then
      sz=$(stat -c %s "$file" 2>/dev/null || echo 0)
      if [ "$sz" -gt "$threshold_bytes" ] || { [ "$force" = "force" ] && [ "$sz" -gt 0 ]; }; then file_due=1; else file_due=0; fi
    elif [ -n "${pend[$file]:-}" ]; then
      file_due=1                                    # deferred earlier: still due until it is handled
    fi
    if [ -n "${PG_STOP:-}" ]; then
      # the service is stopping: due live files not reached yet are retried first thing at the next start
      [ "$file_due" = 1 ] && [[ "$file" != */"$PG_COPY_DIR"/* ]] && ! pg_old_name "${file##*/}" && pend_new[$file]=1
      continue
    fi
    pg_process_file "$file" "$file_due" "$dry" "$verbose" "$force"
    freed=$(( freed + PG_FREED ))
    [ "$PG_OUTCOME" = "acted" ] && acted=$(( acted + 1 ))
    [ "$PG_LIVE" = "acted" ]   && live_acted=1
    [ "$PG_LIVE" = "pending" ] && { live_pending=1; [ "$file_due" = "1" ] && pend_new[$file]=1; }
  done

  if [ "$dry" = "1" ]; then
    [ "$acted" -gt 0 ] && [ -z "$verbose" ] && printf "  %b %s  ${C_DIM}->${C_RESET} would process %s files, %s freed\n" \
      "$(dot "$C_YELLOW")" "$TARGET_PATH" "$acted" "$(human "$freed")"
    return 0
  fi

  # Schedule bookkeeping: a time-based path restarts its interval whenever it was due. Files that had to be
  # deferred are in the pending list and retried on their own - they no longer keep the whole path due.
  new_lp=$LAST_PURGE
  if [ "$RETENTION_UNIT" = "mb" ]; then
    [ "$live_acted" = "1" ] && new_lp=$now_epoch
  else
    [ "$due" = "1" ] && new_lp=$now_epoch
  fi
  if [ "$new_lp" != "$LAST_PURGE" ] || [ "$freed" -gt 0 ] || [ "$f" != "$PATHS_DIR/$id.conf" ]; then
    ( with_conf_lock conf_update_run "$f" "$id" "$TARGET_PATH" "$PATTERN" "$new_lp" \
        "$([ "$freed" -gt 0 ] && echo "$freed" || echo "$LAST_FREED")" )
  fi
  # remember the live files that are still waiting (retried every pass, see above)
  if [ "$RETENTION_UNIT" != "mb" ]; then
    if [ "${#pend_new[@]}" -gt 0 ]; then
      mkdir -p "$PG_PENDING_DIR" 2>/dev/null && chmod 700 "$PG_PENDING_DIR" 2>/dev/null
      printf '%s\0' "${!pend_new[@]}" > "$pend_file.tmp.$$" && mv -f "$pend_file.tmp.$$" "$pend_file"
    else
      rm -f "$pend_file"
    fi
  fi
  [ "$freed" -gt 0 ] && log_success "reclaimed $(human "$freed") in $TARGET_PATH (${RETENTION_VALUE}${RETENTION_UNIT})"
  return 0
}

# conf_update_run <conf file> <id> <target> <pattern> <last_purge> <last_freed> - the service's write-back after
# a pass. It re-reads the conf (under with_conf_lock) and changes only the two bookkeeping values, so a path that
# was removed, disabled or edited from the console while the pass ran keeps that change. A conf whose file
# name is not the id of its target+pattern is moved to the right name (otherwise it would be due on every pass).
conf_update_run() {
  local f="$1" id="$2" t0="$3" p0="$4" lp="$5" lf="$6"
  [ -e "$f" ] || return 0                                            # removed meanwhile
  load_conf "$f" || return 0
  { [ "$TARGET_PATH" = "$t0" ] && [ "$PATTERN" = "$p0" ]; } || return 0  # edited meanwhile: leave it alone
  rewrite_path_conf "$f" "$id" "$TARGET_PATH" "$PATTERN" "$RETENTION_VALUE" "$RETENTION_UNIT" "$ENABLED" "$lp" "$lf"
}

# do_worker [verbose] [force] [dry_run]
do_worker() {
  local verbose="${1:-}" force="${2:-}" dry="${3:-}"
  local f
  [ "$dry" = "1" ] || { pg_watch_all; pg_copies_sweep; }
  for f in $(list_confs); do
    purge_one_path "$f" "$verbose" "$force" "$dry" || log_error "worker failed processing: $f"
  done
  [ "$dry" = "1" ] || pg_clean_aside
}

dry_run_preview() {
  header
  echo "${C_BOLD}Dry-run / preview mode${C_RESET} - no files will be modified."
  echo
  do_worker "verbose" "" "1"
  echo
  det_deleted_open_report
  echo
  info_msg "Nothing was changed. Run a manual purge to apply these actions."
  pause
}

# ============================================================
# SECTION: Main Menu
# ============================================================
# settings_edit <KEY> - change one setting interactively
settings_edit() {
  local key="$1" t def label cur ans msg
  t=$(settings_field "$key" 2); def=$(settings_field "$key" 3); label=$(settings_field "$key" 5)
  while true; do
    header
    echo "${C_BOLD}${label}${C_RESET}"
    echo "${C_DIM}setting ${key}  ·  default: $(settings_show "$key" "$def")  ·  now: $(settings_show "$key")  (${SETTINGS_FROM[$key]:-default})${C_RESET}"
    echo
    if [[ "$t" == list:* ]]; then
      local i=0 item; declare -a items=()
      while IFS= read -r item; do i=$(( i + 1 )); items[$i]="$item"; printf "   ${C_CYAN}%2s${C_RESET} %s\n" "$i" "$item"; done < <(list_items "$key")
      [ "$i" = 0 ] && echo "   ${C_DIM}(empty)${C_RESET}"
      echo
      menu_row "a" "Add an item"; menu_row "d" "Delete an item"; menu_row "r" "Reset to default"; menu_row "0" "Back"
      read -rp "Choose: " ans || menu_eof
      case "$ans" in
        a|A) read -rp "New item: " item; [ -n "$item" ] || continue
             settings_reload_if_changed          # add to the list as it is on disk now, not as it was shown
             # settings_set runs in a subshell here (to capture its message), so reload its result into this shell
             if msg=$(settings_set "$key" "${!key:+${!key}|}$item"); then settings_load; success_msg "Added."; else error_msg "$msg"; fi; pause;;
        d|D) read -rp "Delete item number: " ans
             if [ "$(stat -c '%y %i' "$SETTINGS_FILE" 2>/dev/null)" != "$SETTINGS_MTIME" ]; then
               settings_load; error_msg "The settings were changed elsewhere meanwhile - check the list again."; pause; continue
             fi
             [[ "$ans" =~ ^[0-9]{1,6}$ ]] && ans=$(( 10#$ans ))
             if [[ "$ans" =~ ^[0-9]+$ ]] && [ -n "${items[$ans]:-}" ]; then
               local keep="" j; for (( j=1; j<=i; j++ )); do [ "$j" = "$ans" ] || keep+="${keep:+|}${items[$j]}"; done
               if [ -z "$keep" ] && [ -n "$def" ]; then
                 # an empty list must still differ from the default, so store a single empty marker
                 settings_save "$key" "" && printf '%s=""\n' "$key" >> "$SETTINGS_FILE" && settings_load
               else
                 settings_set "$key" "${keep:-default}" >/dev/null
               fi
               success_msg "Deleted."
             else error_msg "No such item."; fi; pause;;
        r|R) settings_set "$key" default >/dev/null; success_msg "Back to default."; pause;;
        *) return;;
      esac
    else
      case "$t" in
        dur)  echo "Enter a time, e.g. 30s, 15m, 2h, 1d";;
        pct)  echo "Enter a percentage, e.g. 90";;
        bool) echo "Enter on or off";;
        size) echo "Enter a size, e.g. 64MB, 1GB";;
        hhmm) echo "Enter a time of day, e.g. 23:55";;
        path) echo "Enter an absolute path";;
        dirname) echo "Enter a folder name, e.g. purged (it is made inside each log's own folder), or off";;
        copyname) echo "Enter the copy name. {name} = the log's name, {ext} = its ending (.log); date codes give its delete time:"
                  echo "  %d day  %b month (Nov)  %Y year  %I hour (12h)  %H hour (24h)  %M min  %S sec  %p AM/PM  %Z time zone"
                  echo "  now: $(LC_ALL=C date -d "@$(( $(date +%s) + PG_GRACE_SEC ))" +"$PG_COPY_NAME" | sed 's/{name}/app/; s/{ext}/.log/')  (for app.log)";;
      esac
      read -rp "New value (Enter = keep, 'default' = reset): " ans
      [ -n "$ans" ] || return
      # settings_set runs in a subshell here (to capture its message), so reload its result into this shell
      if msg=$(settings_set "$key" "$ans"); then settings_load; success_msg "Saved: $(settings_show "$key")"; else error_msg "$msg"; fi
      pause; return
    fi
  done
}

# settings_menu - every engine setting, grouped, editable
settings_menu() {
  local key t def grp label last n i cur
  while true; do
    header
    echo "${C_BOLD}Settings${C_RESET} ${C_DIM}- everything the purge engine uses. Saved in ${SETTINGS_FILE};"
    echo "the background service picks changes up within seconds. ${C_YELLOW}*${C_DIM} = changed from the default.${C_RESET}"
    i=0; last=""; declare -a keys=()
    while IFS=$'\t' read -r key t def grp label; do
      [ -n "$key" ] || continue
      [ "$grp" != "$last" ] && { menu_section "$grp"; last=$grp; }
      i=$(( i + 1 )); keys[$i]=$key
      cur="${!key:-}"
      printf "   ${C_CYAN}%2s${C_RESET} %-66s %s%s\n" "$i" "$label" "$(settings_show "$key")" "$([ "$cur" != "$def" ] && echo " ${C_YELLOW}*${C_RESET}")"
    done <<<"$SETTINGS_REGISTRY"
    echo; echo "   ${C_DIM}Always protected (operating system): ${PG_PROTECT_FLOOR[*]}${C_RESET}"
    menu_section ""; menu_row "0" "Back"
    echo
    read -rp "Change which setting (number): " n
    case "$n" in ""|0) return;; esac
    [[ "$n" =~ ^[0-9]{1,6}$ ]] && n=$(( 10#$n ))
    if [[ "$n" =~ ^[0-9]+$ ]] && [ -n "${keys[$n]:-}" ]; then settings_edit "${keys[$n]}"; else echo "${C_RED}Invalid choice.${C_RESET}"; sleep 1; fi
  done
}

# path_options_prompt - ask for the per-path hold time and in-place option (Enter keeps the current / default)
path_options_prompt() {
  local ans v
  echo
  echo "${C_BOLD}Rotated copies of this path${C_RESET} - hold before deleting. Now: $( [ -n "${HOLD_SEC:-}" ] && human_secs "$HOLD_SEC" || echo "default ($(human_secs "$PG_GRACE_SEC"))")"
  read -rp "  Hold time (e.g. 2h, 1d; Enter = keep; 'default' = use the setting): " ans
  if [ "$ans" = "default" ]; then HOLD_SEC=""
  elif [ -n "$ans" ]; then v=$(parse_duration_sec "$ans") && HOLD_SEC="$v" || echo "  ${C_YELLOW}not a time - hold left unchanged${C_RESET}"; fi
  echo "${C_BOLD}Empty in place${C_RESET} when a file cannot be rotated. Now: $(case "${PATH_ALLOW_TRUNCATE:-}" in 1) echo on;; 0) echo off;; *) echo "default ($([ "$PG_ALLOW_TRUNCATE" = 1 ] && echo on || echo off))";; esac)"
  read -rp "  on / off / default (Enter = keep): " ans
  case "${ans,,}" in on|yes|1) PATH_ALLOW_TRUNCATE=1;; off|no|0) PATH_ALLOW_TRUNCATE=0;; default) PATH_ALLOW_TRUNCATE="";; esac
}

main_menu() {
  while true; do
    settings_reload_if_changed     # pick up a --set or another console's change before showing anything
    dashboard
    echo
    hr "-"
    echo "${C_BOLD}Menu${C_RESET}"

    menu_section "PATHS"
    menu_row "1" "Refresh dashboard"
    menu_row "2" "Add a purge path"
    menu_row "3" "Edit a path (retention / pattern)"
    menu_row "4" "Enable / disable a path"
    menu_row "5" "Remove a path from management"

    menu_section "EXECUTION"
    menu_row "6" "Run purge now (manual, force)"
    menu_row "7" "Dry-run preview (no changes made)"
    menu_row "8" "Plan: what the tool found and will do with each path (read-only)"
    menu_row "9" "Inspect a path: who writes / reads it (read-only)"

    menu_section "SETTINGS"
    menu_row "10" "Settings (hold time, protection, readers, timings, quiet window, updates)"

    menu_section "SERVICE"
    menu_row "11" "Service control (start / stop / restart)"
    menu_row "12" "Re-run setup / reinstall service"

    menu_section "DIAGNOSTICS"
    menu_row "13" "View purge log"
    menu_row "14" "Health check"
    menu_row "15" "Statistics"
    menu_row "16" "System information"
    menu_row "17" "Repair configuration"

    menu_section "BACKUP"
    menu_row "18" "Backup configuration"
    menu_row "19" "Export configuration"

    menu_section ""
    menu_row "0" "Exit"
    echo
    read -rp "Select an option: " opt || menu_eof
    case "$opt" in
      1) ;;                       # loop re-renders dashboard
      2) add_path;;
      3) edit_path;;
      4) toggle_path;;
      5) remove_path;;
      6) run_purge_now;;
      # (the letters of v2.6.11 and older still work, unlisted: d p x c h s i r b e)
      7|d|D) dry_run_preview;;
      8|p|P) header; plan_all; pause;;
      9|x|X) header; read -rp "File or directory to inspect: " xp; [ -n "$xp" ] && detect_report "$xp"; pause;;
      10|c|C) settings_menu;;
      11) service_control;;
      12) first_time_setup;;
      13) view_log;;
      14|h|H) health_check;;
      15|s|S) show_stats;;
      16|i|I) show_system_info;;
      17|r|R) repair_configuration;;
      18|b|B) header; backup_configuration; pause;;
      19|e|E) header; read -rp "Export to file path: " ef; [ -n "$ef" ] && export_configuration "$ef"; pause;;
      0) echo "Goodbye."; exit 0;;
      *) echo "${C_RED}Invalid option.${C_RESET}"; sleep 1;;
    esac
  done
}

# ============================================================
# SECTION: CLI - add subcommand
# ============================================================
# service_start_guarded - starting the service begins real deletions, so it must never happen by a reflex "y":
# show what will be processed and require the word "start".
service_start_guarded() {
  local n=0 f ans
  for f in $(list_confs); do load_conf "$f" >/dev/null 2>&1 && [ "$ENABLED" = 1 ] && n=$(( n + 1 )); done
  echo
  echo "${C_BOLD}Starting the purge service${C_RESET} - from now on it rotates and deletes files on its own."
  echo "  ${C_CYAN}${n}${C_RESET} enabled path(s) will be processed right away (purge pass every $(human_secs "$PG_PASS_SEC"))."
  echo "  ${C_DIM}Check first what it will do: menu 8 (Plan) or: purgingconsole --plan${C_RESET}"
  read -rp "Type start to start it (anything else cancels): " ans
  if [ "$ans" != "start" ]; then echo "Not started."; return 1; fi
  if systemctl enable --now "${SERVICE_NAME}.service" >/dev/null 2>&1; then
    success_msg "Service enabled and running."; log_success "service enabled (confirmed by typing start)"
  else
    error_msg "Failed to enable service."; log_error "failed to enable service"; return 1
  fi
}

# ============================================================
# SECTION: Plan - what the engine found and what it will do, per file (read-only)
# ============================================================
# plan_schedule_text - the configured retention in words (uses the loaded path config)
plan_schedule_text() {
  case "$RETENTION_UNIT" in
    midnight) echo "once a day at ${PG_DAILY_AT:0:2}:${PG_DAILY_AT:2:2}";;
    mb)       echo "whenever it grows past ${RETENTION_VALUE} MB";;
    *)        echo "every ${RETENTION_VALUE} ${RETENTION_UNIT}";;
  esac
}

# plan_who <file> - "written by" / "read by" lines (open files + configured readers)
plan_who() {
  local f="$1" pid comm k rw app pos size cmd pat src one w="" r="" lag
  declare -A seen=() rmax=() rname=()
  size=$(stat -c %s "$f" 2>/dev/null || echo 0)
  while IFS='|' read -r pid comm k rw app pos; do
    [ -n "$pid" ] || continue
    if [ "$rw" = "r" ]; then
      # a reader can hold the file more than once (rsyslog does): its furthest position counts
      if [ -z "${rmax[$pid]:-}" ] || [ "$pos" -gt "${rmax[$pid]}" ]; then rmax[$pid]=$pos; fi
      rname[$pid]="$comm$([ "$k" != other ] && echo " ($k)")"
    else
      [ -n "${seen[w$pid]:-}" ] && continue; seen[w$pid]=1
      if cmd=$(pg_reload_cmd_for "$pid" "$k"); then cmd="can reopen"; else cmd="cannot be told to reopen"; fi
      w+="${w:+, }$comm$([ "$k" != other ] && echo " ($k)") - $cmd$([ "$app" = 1 ] || echo ", NOT append mode")"
    fi
  done < <(DET_BY_INODE=1 det_proc_users "$f")
  for pid in "${!rmax[@]}"; do
    lag=$(( size - rmax[$pid] )); [ "$lag" -lt 0 ] && lag=0
    r+="${r:+, }${rname[$pid]}$([ "$lag" -gt 0 ] && echo ", $(human "$lag") behind" || echo ", up to date")"
  done
  while IFS= read -r pat; do
    det_glob_match "$f" "$pat" && [[ "$r" != *rsyslog* ]] && r+="${r:+, }rsyslog imfile (configured, not reading now)"
  done < <(det_rsyslog_patterns)
  while IFS='|' read -r pat src excl; do
    IFS=',' read -ra _pw_a <<<"$pat"
    for one in "${_pw_a[@]}"; do
      one="${one// /}"; det_glob_match "$f" "$one" || continue; det_fluentd_excluded "$f" "$excl" && continue
      [[ "$r" == *fluentd* ]] || r+="${r:+, }fluentd (configured; position file ${src##*/})"
      break
    done
  done < <(det_fluentd_sources)
  while IFS= read -r pat; do
    det_glob_match "$f" "$pat" && [[ "$r" != *wazuh* ]] && r+="${r:+, }Wazuh logcollector (configured)"
  done < <(det_wazuh_patterns)
  printf "      written by: %s\n" "${w:-nobody right now}"
  printf "      read by:    %s\n" "${r:-nobody found}"
}

# path_plan <target> <pattern> - needs the path's config loaded (load_conf) or set up like it
path_plan() {
  local target="$1" pattern="$2" f n=0 total=0 shown=0 out tmp base kind age why maxshow=12
  det_cache_refresh
  echo
  echo "${C_BOLD}Plan for ${target}${C_RESET}${C_DIM}  (pattern ${pattern}; ${RETENTION_VALUE} ${RETENTION_UNIT}; rotated copies held $(human_secs "${HOLD_SEC:-$PG_GRACE_SEC}"); empty in place: $([ "${PATH_ALLOW_TRUNCATE:-$PG_ALLOW_TRUNCATE}" = 1 ] && echo on || echo off))${C_RESET}"
  [ -d "$target" ] || { echo "   ${C_YELLOW}the folder does not exist yet - nothing to do until it does${C_RESET}"; return 0; }
  tmp=$(mktemp)
  # newest files first (the live ones are normally the newest). Listed by find alone, not per file: a big
  # folder (/opt) holds many thousands of files and only the first few are shown. Copy folders are listed apart.
  local -a pprune=()
  [ "$PG_COPY_DIR" != off ] && pprune=( -mindepth 1 \( -type d -name "$PG_COPY_DIR" -prune \) -o )
  while IFS= read -r -d '' f; do
    [ -e "$f" ] || continue          # removed while the plan was being built (e.g. by the running service)
    # a file in a copy folder that is not one of our copies is never touched by the engine: not listed
    if pg_in_copy_dir "$f" && ! pg_copy_info "$f" "${HOLD_SEC:-$PG_GRACE_SEC}"; then continue; fi
    total=$(( total + 1 ))
    [ "$shown" -ge "$maxshow" ] && continue
    shown=$(( shown + 1 ))
    base="${f##*/}"; kind="live log"; local pcdue=""
    if pg_copy_info "$f" "${HOLD_SEC:-$PG_GRACE_SEC}"; then pcdue=$PG_COPY_DUE; kind="rotated copy, deleted at $(pg_when "$pcdue")"
    elif pg_rotated_name "$base"; then kind="already rotated"; elif pg_dated_name "$base"; then kind="date-named (finished once its day is over)"; fi
    age=$(( ( $(date +%s) - $(stat -c %Y "$f" 2>/dev/null || date +%s) ) / 3600 ))
    printf "   %s %s  ${C_DIM}(%s, %s, last written %sh ago)${C_RESET}\n" "$(dot "$C_CYAN")" "$f" "$kind" "$(human "$(stat -c %s "$f" 2>/dev/null || echo 0)")" "$age"
    plan_who "$f"
    PG_PLAN_QUIET=1 pg_process_file "$f" 1 1 "v" "force" > "$tmp" 2>/dev/null
    out=$(sed 's/\x1b\[[0-9;]*m//g; s/^.*  -> //; s/^dry-run: //' "$tmp" | tail -1)
    if [ -n "$out" ]; then
      case "$out" in
        would\ rotate*) out="rotate it $(plan_schedule_text); keep the old copy $([ "$PG_COPY_DIR" != off ] && echo "in ${f%/*}/$PG_COPY_DIR/ ")for $(human_secs "${HOLD_SEC:-$PG_GRACE_SEC}"), then delete it once every reader has finished";;
        would\ delete*) out="delete it now: older than ${RETENTION_VALUE} ${RETENTION_UNIT} and every reader has finished it";;
        would\ retire*) out="set it aside and delete it after $(human_secs "${HOLD_SEC:-$PG_GRACE_SEC}") (nobody writes it any more)";;
        would\ truncate*) out="empty it in place $(plan_schedule_text) (writer cannot reopen; allowed for this path)";;
      esac
    elif [ "$PG_OUTCOME" = skipped ] || [ "$PG_OUTCOME" = deferred ]; then
      out="leave it alone for now - ${PG_WHY}"
    elif [ -n "$pcdue" ]; then
      out="keep it until $(pg_when "$pcdue") (earlier only if the disk reaches ${PG_DISK_EMERGENCY_PCT}%), then delete it once every reader has finished"
    elif pg_old_name "$base"; then
      out="keep it until it is older than ${RETENTION_VALUE} ${RETENTION_UNIT}, then delete it once every reader has finished"
    elif [ "$(stat -c %s "$f" 2>/dev/null || echo 0)" -eq 0 ]; then
      out="nothing to do (empty file)"
    else
      out="nobody writes it now; once it is older than ${RETENTION_VALUE} ${RETENTION_UNIT} it is set aside, kept $(human_secs "${HOLD_SEC:-$PG_GRACE_SEC}"), then deleted"
    fi
    printf "      plan:       %s\n" "$out"
  done < <( { find "$target" ${pprune[@]+"${pprune[@]}"} -type f \( -name "$pattern" -o -name "${pattern}.purge-*" \) -printf '%T@\t%p\0' 2>/dev/null
              [ "$PG_COPY_DIR" != off ] && find "$target" -mindepth 1 -type d -name "$PG_COPY_DIR" -prune \
                  -exec find {} -mindepth 1 -maxdepth 1 -type f -printf '%T@\t%p\0' \; 2>/dev/null
            } | sort -z -t$'\t' -k1,1nr | cut -z -f2-)
  rm -f "$tmp"
  [ "$total" -eq 0 ] && echo "   ${C_DIM}no matching files yet - they will be handled as they appear${C_RESET}"
  [ "$total" -gt "$shown" ] && echo "   ${C_DIM}... and $(( total - shown )) more file(s), handled the same way${C_RESET}"
  det_conflicts_report "$target" "$pattern" | sed 's/^/   /'
  return 0
}

# plan_all [path-filter] - the plan for every configured path (or the ones under the filter)
plan_all() {
  local f n=0
  for f in $(list_confs); do
    load_conf "$f" >/dev/null 2>&1 || continue
    [ -n "${1:-}" ] && [[ "$TARGET_PATH/$PATTERN" != "${1%/}"* ]] && [[ "${1%/}" != "$TARGET_PATH"* ]] && continue
    n=$(( n + 1 )); path_plan "$TARGET_PATH" "$PATTERN"
  done
  [ "$n" -gt 0 ] || echo "No configured path${1:+ matches $1}."
}

# parse_duration_sec <30s|15m|2h|1d|3600> -> seconds
parse_duration_sec() {
  [[ "$1" =~ ^([0-9]{1,9})(s|m|min|h|d)?$ ]] || return 1
  local n=$(( 10#${BASH_REMATCH[1]} ))     # decimal: "08" must not stop the script as a bad octal number
  case "${BASH_REMATCH[2]}" in ""|s) echo "$n";; m|min) echo $(( n * 60 ));; h) echo $(( n * 3600 ));; d) echo $(( n * 86400 ));; esac
}

# human_secs <seconds> -> "45s" / "30m" / "2h" / "1d"
human_secs() {
  local n=${1:-0}
  if [ "$n" -ge 86400 ] && [ $(( n % 86400 )) -eq 0 ]; then echo "$(( n / 86400 ))d"
  elif [ "$n" -ge 3600 ] && [ $(( n % 3600 )) -eq 0 ]; then echo "$(( n / 3600 ))h"
  elif [ "$n" -ge 60 ] && [ $(( n % 60 )) -eq 0 ]; then echo "$(( n / 60 ))m"
  else echo "${n}s"; fi
}

# cmd_remove <path> - stop managing a path (no files are touched). Same forms as add:
#   /dir   /dir/file.log   "/dir/pattern*"
cmd_remove() {
  local arg="${1:-}" target pattern f n=0
  [ -n "$arg" ] || { echo "Usage: purgingconsole remove <path>   (see: purgingconsole --list)"; exit 1; }
  arg="${arg%/}"
  if [ -d "$arg" ]; then target="$arg"; pattern="*"
  else target=$(dirname "$arg"); pattern=$(basename "$arg"); fi
  local ctarget carg; ctarget=$(realpath -m -- "$target" 2>/dev/null || echo "$target"); carg=$(realpath -m -- "$arg" 2>/dev/null || echo "$arg")
  for f in $(list_confs); do
    load_conf "$f" >/dev/null 2>&1 || continue
    if { { [ "$TARGET_PATH" = "$target" ] || [ "$TARGET_PATH" = "$ctarget" ]; } && [ "$PATTERN" = "$pattern" ]; } \
       || { { [ "$TARGET_PATH" = "$arg" ] || [ "$TARGET_PATH" = "$carg" ]; } && [ "$PATTERN" = "*" ]; }; then
      with_conf_lock rm -f "$f"; n=$(( n + 1 ))
      echo "Removed from management: ${TARGET_PATH}  (pattern: ${PATTERN})  - no files were touched"
      log_info "CLI remove: ${TARGET_PATH}/${PATTERN}"
    fi
  done
  [ "$n" -gt 0 ] || { echo "No configured path matches '$arg'. Configured paths:"; cmd_list | sed 's/^/  /'; exit 1; }
}

cmd_add() {
  local target="${1:-}" ret="${2:-}" hold="" trunc=""
  shift 2 2>/dev/null || true
  while [ $# -gt 0 ]; do
    case "$1" in
      --hold)     hold=$(parse_duration_sec "${2:-}") || die "invalid --hold '${2:-}' - use e.g. 30m, 2h, 1d"; shift 2;;
      --truncate) case "${2:-}" in on) trunc=1;; off) trunc=0;; default) trunc="";; *) die "use --truncate on|off|default";; esac; shift 2;;
      *) die "unknown option '$1' (use --hold <time> or --truncate on|off)";;
    esac
  done
  if [ -z "$target" ] || [ -z "$ret" ]; then
    echo "Usage: purgingconsole add <path> <retention> [--hold <time>]"
    echo "  path:      a file, a directory, or directory/pattern (e.g. /data/app/*.jsonl - searched recursively)"
    echo "  retention: 1h  6h  1d  7d  2w  1m  midnight  100mb"
    echo "  --hold:    keep each rotated copy this long before deleting it (default: setting PG_GRACE_SEC), e.g. 2h"
    echo "  --truncate on|off: allow emptying in place for this path when it cannot be rotated (default: setting)"
    echo
    echo "Examples:"
    echo "  purgingconsole add /root/test.log 1d"
    echo "  purgingconsole add /var/log/myapp 7d"
    echo "  purgingconsole add /var/log/app.log 2h"
    exit 1
  fi

  target="${target%/}"
  local msg; if ! msg=$(is_safe_path "$target"); then die "$msg"; fi

  local parsed value unit
  if ! parsed=$(parse_retention "$ret"); then
    die "invalid retention '$ret' - use formats like 1h, 6h, 1d, 7d, 2w, 1m"
  fi
  read -r value unit <<< "$parsed"

  local pattern
  if [ -f "$target" ]; then
    pattern=$(basename "$target"); target=$(dirname "$target")
  elif [ -d "$target" ]; then
    pattern="*"
  else
    local base; base=$(basename "$target")
    if [[ "$base" == *.* ]]; then pattern="$base"; target=$(dirname "$target")
    else pattern="*"; fi
  fi
  # check the folder that will really be searched, not just what was typed ("/*.log" would be all of /)
  check_new_path "$target" "$pattern" || die "$NP_ERR"
  target=$NP_TARGET

  mkdir -p "$PATHS_DIR"; chmod 700 "$CONF_DIR" "$PATHS_DIR" 2>/dev/null

  local id; id=$(path_id "${target}/${pattern}")
  local display_path initial_lp=0
  [ "$unit" = "midnight" ] && initial_lp=$(date +%s)
  if [[ "$pattern" != *"*"* ]]; then display_path="${target}/${pattern}"; else display_path="${target}  (pattern: ${pattern})"; fi
  HOLD_SEC="$hold"; PATH_ALLOW_TRUNCATE="$trunc"
  if with_conf_lock replace_path_conf "$target" "$pattern" "$value" "$unit" 1 "$initial_lp" 0; then
    echo "Added: '${display_path}'  →  retain last ${value} ${unit}${hold:+, rotated copies held $(human_secs "$hold")}"
    log_info "CLI add: ${target}/${pattern} retention=${value}${unit}${hold:+ hold=${hold}s}"
    load_conf "$PATHS_DIR/$id.conf" >/dev/null 2>&1 && path_plan "$target" "$pattern"
  else
    die "failed to write config - check permissions on $PATHS_DIR"
  fi
}

# ============================================================
# SECTION: CLI - status/health/validate/list output
# ============================================================
cmd_status() {
  echo "${APP_NAME} v${APP_VERSION}"
  if systemctl is-active --quiet "${SERVICE_NAME}.service" 2>/dev/null; then
    echo "service: active"
  else
    echo "service: inactive"
  fi
  collect_stats
  echo "paths: total=${STAT_TOTAL} enabled=${STAT_ENABLED} disabled=${STAT_DISABLED} invalid=${STAT_INVALID}"
  echo "last_run: $(rel_time "$STAT_LAST_RUN")"
  echo "lifetime_reclaimed: $(human "$STAT_TOTAL_FREED")"
}

cmd_validate() {
  local f bad=0 total=0
  for f in $(list_confs); do
    total=$(( total + 1 ))
    if ! load_conf "$f" >/dev/null 2>&1; then
      echo "INVALID: $f"
      bad=$(( bad + 1 ))
    fi
  done
  echo "checked ${total} config(s), ${bad} invalid"
  [ "$bad" -eq 0 ]
}

cmd_list() {
  local f
  for f in $(list_confs); do
    if load_conf "$f" >/dev/null 2>&1; then
      printf '%s\t%s\t%s%s\t%s\thold=%s\n' "$TARGET_PATH" "$PATTERN" "$RETENTION_VALUE" "$RETENTION_UNIT" "$([ "$ENABLED" = "1" ] && echo enabled || echo disabled)" "$(human_secs "${HOLD_SEC:-$PG_GRACE_SEC}")"
    fi
  done
}

# ============================================================
# SECTION: Entry Point
# ============================================================
usage() {
  cat <<EOF
${APP_NAME} v${APP_VERSION}

Usage: purgingconsole [command] [options]

Commands:
  (none)              Launch interactive console
  add <path> <ret>    Add a purge path non-interactively (e.g. add /var/log/app.log 1d)
  remove <path>       Stop managing a path (same forms as add; no files are touched)
  purge               Force-purge all enabled paths immediately

Options:
  --watch             Run the realtime watcher loop (used by the systemd service)
  --worker            Run a single worker pass and exit
  --status            Print a one-shot status summary
  --health            Run health check diagnostics and exit
  --validate          Validate all path configs and exit (non-zero if any invalid)
  --dry-run           Preview what a purge would do without modifying files
  --detect <path>     Read-only: show who writes/reads a file (rsyslog, Fluentd, Wazuh, ...)
  --plan [path]       Read-only: what the tool found (writers, readers, file kinds) and will do with each path
  --watches           Read-only: list rotated copies whose readers are still being watched
  --held-deleted      Read-only: deleted log files still held open by a process (disk not freed)
  --settings          Show every engine setting (current value, default, description)
  --set KEY VALUE     Change a setting (e.g. --set PG_GRACE_SEC 12h;  lists: "a|b|c";  VALUE 'default' resets)
  --unset KEY         Put a setting back to its default
  --check <file>      Read-only: what the purge engine would conclude about one file now
  --list              List configured paths (tab-separated)
  --stats             Print aggregate statistics
  --backup [file]     Back up configuration to a tar.gz archive
  --restore <file>    Restore configuration from a tar.gz archive
  --export <file>     Export path configs to a plain-text file
  --import <file>     Import path configs from a previously exported file
  --repair            Quarantine corrupted configs and reset permissions
  --debug             Enable debug-level logging for this invocation
  --verbose           Enable verbose console output for this invocation
  --update            Install the newest version, if there is one (asks first; --yes: no question)
  --update --check    Only tell whether a newer version exists, and what changed
                      (automatic, once a day:  --set PG_AUTO_UPDATE on   [time: PG_AUTO_UPDATE_AT, default 03:00])
  --version           Print version information
  --help              Show this help text
EOF
}

# ============================================================
# SECTION: Update - one command to move to the newest version
# ============================================================
# The newest version is the purging-console.sh at PG_UPDATE_URL (the releases repo's main branch only ever
# holds released versions). It is downloaded, checked (checksum if published, bash syntax, version number),
# and put in place the same way the installer does it: a new file renamed over the old one, so a running
# service keeps its own copy until it is restarted on the new version.

# pg_fetch <url> <out file> - 0 when downloaded (HTTP errors fail)
pg_fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL --max-time 60 -o "$2" "$1" 2>/dev/null
  elif command -v wget >/dev/null 2>&1; then wget -q -T 60 -O "$2" "$1" 2>/dev/null
  else echo "error: neither curl nor wget is installed" >&2; return 2; fi
}

# ver_newer <a> <b> - 0 if version a is newer than b (2.6.10 > 2.6.9)
ver_newer() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]; }

cmd_update() {
  local check=0 yes=0 auto=0 a tmp new sum want got log
  for a in "$@"; do
    case "$a" in --check) check=1;; --yes|-y) yes=1;; --auto) auto=1; yes=1;; *) die "unknown option '$a' (use: --update [--check] [--yes])";; esac
  done
  [ "$check" = 1 ] || require_root --update "$@"
  tmp=$(mktemp -d) || die "cannot create a temporary folder"
  echo "Checking ${PG_UPDATE_URL} ..."
  if ! pg_fetch "$PG_UPDATE_URL/purging-console.sh" "$tmp/pc.sh"; then
    rm -rf "$tmp"; echo "error: could not download $PG_UPDATE_URL/purging-console.sh (no internet / proxy / wrong PG_UPDATE_URL?)" >&2
    [ "$auto" = 1 ] && log_warn "auto-update: could not download $PG_UPDATE_URL/purging-console.sh - tried again tomorrow"
    return 1
  fi
  new=$(sed -nE 's/^readonly APP_VERSION="([0-9][0-9.]*)"$/\1/p' "$tmp/pc.sh" | head -1)
  if [ -z "$new" ] || ! grep -q '^readonly APP_NAME="Purging Management Console"' "$tmp/pc.sh"; then
    rm -rf "$tmp"; echo "error: the downloaded file is not this tool - nothing changed" >&2
    [ "$auto" = 1 ] && log_warn "auto-update: $PG_UPDATE_URL/purging-console.sh is not this tool - nothing changed"
    return 1
  fi
  if ! ver_newer "$new" "$APP_VERSION"; then
    rm -rf "$tmp"; echo "Up to date: v${APP_VERSION} is the newest version (newest published: v${new})."; return 0
  fi
  echo "${C_BOLD}New version available: v${new}${C_RESET}  (installed: v${APP_VERSION})"
  # what changed since the installed version (CHANGELOG sections newer than it)
  if pg_fetch "$PG_UPDATE_URL/CHANGELOG.md" "$tmp/CHANGELOG.md"; then
    log=$(awk -v cur="$APP_VERSION" '
      function newer(a, b,  x, y, n, m, i) { n = split(a, x, "."); m = split(b, y, ".")
        for (i = 1; i <= (n > m ? n : m); i++) { if ((x[i] + 0) > (y[i] + 0)) return 1; if ((x[i] + 0) < (y[i] + 0)) return 0 }
        return 0 }
      /^## v[0-9]/ { v = $2; sub(/^v/, "", v); show = newer(v, cur) }
      show' "$tmp/CHANGELOG.md")
    [ -n "$log" ] && { echo; echo "What changed:"; sed 's/^/  /' <<<"$log"; echo; }
  fi
  if [ "$check" = 1 ]; then rm -rf "$tmp"; echo "Install it with: purgingconsole --update"; return 0; fi
  # checksum, when the release publishes one (catches a cut-off download)
  if pg_fetch "$PG_UPDATE_URL/purging-console.sh.sha256" "$tmp/sum"; then
    want=$(awk '{print $1; exit}' "$tmp/sum"); got=$(sha256sum "$tmp/pc.sh" | awk '{print $1}')
    if [ "$want" != "$got" ]; then
      rm -rf "$tmp"; echo "error: checksum does not match (download damaged?) - nothing changed" >&2
      [ "$auto" = 1 ] && log_warn "auto-update: v$new download does not match its checksum - nothing changed"
      return 1
    fi
  fi
  if ! bash -n "$tmp/pc.sh" 2>/dev/null; then
    rm -rf "$tmp"; echo "error: the downloaded file does not parse - nothing changed" >&2
    [ "$auto" = 1 ] && log_warn "auto-update: v$new does not parse - nothing changed"
    return 1
  fi
  if [ "$yes" != 1 ]; then
    confirm "Install v${new} now?" || { rm -rf "$tmp"; echo "Not installed."; return 0; }
  fi
  local dst="${SELF_INSTALL_PATH}.new.$$"
  if ! { cp "$tmp/pc.sh" "$dst" && chmod 755 "$dst" && mv -f "$dst" "$SELF_INSTALL_PATH"; }; then
    rm -f "$dst"; rm -rf "$tmp"; echo "error: could not write $SELF_INSTALL_PATH - nothing changed" >&2; return 1
  fi
  rm -rf "$tmp"
  log_success "$([ "$auto" = 1 ] && echo "auto-update: ")updated from v${APP_VERSION} to v${new} (${PG_UPDATE_URL})"
  echo "Installed: $("$SELF_INSTALL_PATH" --version)"
  if systemctl is-active --quiet "${SERVICE_NAME}.service" 2>/dev/null; then
    if [ "$auto" = 1 ]; then
      # called from the service itself: queue the restart and return - the watcher then gets the stop, finishes
      # the file in hand and exits, and systemd starts it again on the new version
      systemctl --no-block restart "${SERVICE_NAME}.service"
    else
      systemctl restart "${SERVICE_NAME}.service" && echo "The running purge service was restarted on the new version."
    fi
  fi
  return 0
}

# pg_auto_update_tick - from the watcher loop: once a day at PG_AUTO_UPDATE_AT, when PG_AUTO_UPDATE is on
PG_UPDATE_STAMP="/var/lib/purging-console/last-update-check"
pg_auto_update_tick() {
  [ "$PG_AUTO_UPDATE" = 1 ] || return 0
  local today; today=$(date +%F)
  [ $(( 10#$(date +%H%M) )) -ge $(( 10#$PG_AUTO_UPDATE_AT )) ] || return 0
  [ "$(cat "$PG_UPDATE_STAMP" 2>/dev/null)" = "$today" ] && return 0
  mkdir -p "${PG_UPDATE_STAMP%/*}" 2>/dev/null; echo "$today" > "$PG_UPDATE_STAMP"     # once a day, even if it fails
  ( cmd_update --auto ) >/dev/null 2>&1
  return 0
}

main() {
  # Parse global flags anywhere in the argument list without disturbing
  # positional args expected by subcommands like 'add'.
  local args=() a
  for a in "$@"; do
    case "$a" in
      --debug)   DEBUG_MODE=1;;
      --verbose) VERBOSE_MODE=1;;
      *) args+=("$a");;
    esac
  done
  set -- "${args[@]+"${args[@]}"}"
  settings_load

  case "${1:-}" in
    --settings)
      settings_print; echo; echo "${C_DIM}Change with: purgingconsole --set KEY VALUE   (lists: items separated by |;  VALUE 'default' resets)${C_RESET}"; exit 0;;
    --set)
      require_root "$@"; [ -n "${2:-}" ] || die "usage: purgingconsole --set KEY VALUE"
      settings_set "$2" "${3:-}" && echo "$2 = $(settings_show "$2")"; exit $?;;
    --unset)
      require_root "$@"; [ -n "${2:-}" ] || die "usage: purgingconsole --unset KEY"
      settings_set "$2" default && echo "$2 back to default: $(settings_show "$2")"; exit $?;;
    --worker)
      with_lock do_worker; exit 0;;
    --watch)
      do_watch;;
    --status)
      cmd_status; exit 0;;
    --health)
      require_root "$@"; health_check; exit 0;;
    --validate)
      cmd_validate; exit $?;;
    --dry-run)
      do_worker "verbose" "" "1"; echo; det_deleted_open_report; exit 0;;
    --held-deleted)
      require_root "$@"; det_deleted_open_report; exit 0;;
    --list)
      cmd_list; exit 0;;
    --detect)
      require_root "$@"; detect_report "${2:-}"; exit $?;;
    --plan)
      require_root "$@"; plan_all "${2:-}"; exit 0;;
    --watches)
      # rotated copies whose readers are still being watched (reader|pid|start|name|position|state)
      require_root "$@"; _n=0
      for _r in "$PG_WATCH_DIR"/*.watch; do [ -e "$_r" ] || continue; _n=$(( _n + 1 )); echo "== $_r"; sed 's/^/   /' "$_r"; done
      [ "$_n" = 0 ] && echo "No open watch records."; exit 0;;
    --check)
      # what the purge engine would conclude about one file right now (changes nothing)
      require_root "$@"; [ -n "${2:-}" ] || die "usage: purgingconsole --check <file>"
      [ -e "$2" ] || { echo "No such file: $2 (it may already have been purged - see: grep \"${2##*/}\" $LOG_FILE)"; exit 1; }
      pg_consumers_check "$2"; pg_writers_check "$2"
      echo "unread=${PG_UNREAD}B block='${PG_BLOCK}' writers=${PG_WRITERS}$([ -n "$PG_WRITER_CONF" ] && echo " (from the ${PG_WRITER_CONF} config, not open right now)") all_append=${PG_ALL_APPEND} unreloadable=${PG_UNRELOADABLE} reload=[${PG_RELOAD_CMDS[*]:-}]"
      echo "truncate-blockers: $(pg_truncate_blockers "$2")"; exit 0;;
    --stats)
      collect_stats
      echo "total=${STAT_TOTAL} enabled=${STAT_ENABLED} disabled=${STAT_DISABLED} invalid=${STAT_INVALID} last_run=$(rel_time "$STAT_LAST_RUN") reclaimed=$(human "$STAT_TOTAL_FREED")"
      exit 0;;
    --backup)
      require_root "$@"; backup_configuration "${2:-}"; exit $?;;
    --restore)
      require_root "$@"
      [ -n "${2:-}" ] || die "usage: purgingconsole --restore <file>"
      restore_configuration "$2"; exit $?;;
    --export)
      [ -n "${2:-}" ] || die "usage: purgingconsole --export <file>"
      export_configuration "$2"; exit $?;;
    --import)
      require_root "$@"
      [ -n "${2:-}" ] || die "usage: purgingconsole --import <file>"
      import_configuration "$2"; exit $?;;
    --repair)
      require_root "$@"; repair_configuration; exit 0;;
    --version)
      echo "${APP_NAME} v${APP_VERSION} (config schema v${CONFIG_SCHEMA_VERSION})"; exit 0;;
    --update)
      shift; cmd_update "$@"; exit $?;;
    --help|-h)
      usage; exit 0;;
    add)
      require_root "$@"; shift; cmd_add "$@"; exit 0;;
    remove)
      require_root "$@"; shift; cmd_remove "$@"; exit 0;;
    purge)
      require_root "$@"
      echo "${C_BOLD}Force-purging all enabled paths...${C_RESET}"
      PG_LOCK_WAIT=900 with_lock do_worker "verbose" "force"
      success_msg "Done."
      exit 0;;
    "")
      require_root "$@"
      if [ ! -f "$MARKER" ]; then first_time_setup || exit 0; fi
      main_menu;;
    *)
      # a mistyped option (--stat, --dryrun) used to open the menu - and from cron that loops forever
      echo "unknown option '$1' - see: purgingconsole --help" >&2; exit 2;;
  esac
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  main "$@"
fi
