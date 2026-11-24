# Purging Management Console: changelog

**Update (v2.6.11 and later):** `sudo purgingconsole --update` checks for a newer version, shows what changed,
asks, installs it and restarts the service. `--update --check` only tells; `--update --yes` does not ask.
**First install, or a server still on v2.6.10 or older:** paste `install-purging-console.sh` into a root shell
once. Check the version with `purgingconsole --version`.

## v2.6.13 (2026-11-24)
- The automatic update time is IST on every server, whatever the server's own clock: 03:00 means 03:00 IST
  on a UTC server too. New setting `PG_AUTO_UPDATE_TZ` (default `Asia/Kolkata`; `server` = the server's clock).
- Every automatic check now leaves a line in the log, also when nothing newer was found
  (`auto-update: checked, v2.6.13 is the newest`).

## v2.6.12 (2026-11-24)
- Main menu: every option has a number now (1 to 19, 0 = Exit) instead of numbers mixed with letters.
  Settings is 10, Service control 11. The old letters still work.
- Retention presets and the daily schedule are chosen with numbers too.
- Screen messages and comments use plain punctuation.

## v2.6.11 (2026-11-24)
- **One-command update:** `purgingconsole --update` (see the top of this file). The download is checked
  (published checksum, syntax, that it is this tool and newer) before anything is replaced. Source: setting
  `PG_UPDATE_URL`.
- **Automatic update (off by default):** `purgingconsole --set PG_AUTO_UPDATE on` makes the service check
  once a day at `PG_AUTO_UPDATE_AT` (default 03:00) and install a newer version by itself, with the same checks.
- **Default hold is now 1 hour** (was 24 hours): rotated copies are deleted 1 h after rotation unless the path
  has its own `--hold`. Paths with their own hold are unchanged.
- Numbers typed with a leading zero (`08`, `09`) no longer crash the service (bash read them as octal);
  `010` is ten, not eight.
- Retention `0` (`add ... 0h`) is refused: it rotated / deleted on every pass.
- Writers are found by inode, so a program writing through a bind mount or from a container is seen; the file
  is no longer rotated under it.
- Stopping or restarting the service never stops between moving a log and telling its writer to reopen
  (rsyslog was left writing into the moved copy). New installs also get `KillMode=mixed`.
- A live file whose name ends in `.<digits>` (rsyslog per-sender files like `192.168.1.10`) is rotated
  instead of being taken for a finished `app.log.1`.
- rsyslog templates with the date in them (`/remote/%$year%/%$month%/%$day%/syslog.log`) no longer make every
  old day's file count as written by rsyslog.
- Commented-out config is ignored: rsyslog `/* ... */`, Wazuh `<!-- ... -->`.
- fluentd / Wazuh paths with date codes (`%Y-%m-%d`) mean today's and yesterday's file only, so old daily files
  are no longer blocked from deletion forever.
- A file in a `purged/` folder is only taken for one of our copies (without a record) if it is named like one;
  an application's own `purged/` folder is left alone.
- Backup / restore: backups leave out `quarantine/`; restore refuses without a safety backup and reports a
  failure instead of "Restored".
- A mistyped option (`--stat`) exits with an error instead of opening the menu; the menu ends when its input
  ends (no endless loop from cron).

## v2.6.10 (2026-11-21)
- rsyslog counts as the writer of every file its config writes (omfile `file=`, `dynaFile` templates, legacy
  selector lines), also between bursts when it has the file closed. Fixes files skipped after a HUP.
- Rotated copies go into `<log folder>/purged/`, named with their delete time:
  `name_delete-at_22-Nov-2026_at_03-29-37-PM-IST.log`. The delete time is kept in a record and does not move
  if the hold changes later. A link, file, foreign-owned folder or other disk in its place is refused (copies
  then stay beside the log as `<file>.purge-<epoch>`).
- Copies or the whole folder removed by hand are noticed, logged and forgotten; the folder is made again.
- Settings `PG_COPY_DIR`, `PG_COPY_NAME`, `PG_RECENT_WRITE_SEC`. Faster file listing in big folders.

## v2.6.9 (2026-11-21)
- First fix for files skipped after an rsyslog HUP: wait for the writer to reopen when the file was written in
  the last 60 s (partial: bursty disk-queue writers were still missed; completed in v2.6.10).

## v2.6.8 (2026-11-21)
- Settings menu no longer undoes earlier changes; one stuck file no longer makes its whole path due every pass
  (per-file pending list); the conf write-back is locked and re-reads the file.
- `add '/*.log'` refused; confs are parsed, never sourced; import / restore / backup made safe.
- Detection: rsyslog stateFile, fluentd quotes / `**` / `%Y` / exclude_path / chunk names, Wazuh offsets,
  file names with `[`, multi-line logrotate stanzas, logstash.

## v2.6.7 (2026-11-20)
- CPU: with no fluentd the buffer list was re-scanned for every file (a full pass took 60–80 s of CPU); now
  cached. rsyslog inputs cached.
- At the disk limit copies are released oldest first (no gaps). `--status` counts fixed.

## v2.6.6 (2026-11-04)
- Version rolled out to the client servers.
