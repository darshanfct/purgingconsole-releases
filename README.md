# Purging Management Console

Keeps log folders from filling the disk: rotates live logs on a schedule or at a size, tells the writer
(rsyslog, fluentd and others) to reopen, waits until every reader has finished the old copy, and deletes it after a
hold time. Runs as the `purging-console` systemd service; configured with the `purgingconsole` command.

## Install (first time)

As root, paste the whole of [`install-purging-console.sh`](install-purging-console.sh) into the shell, or:

```bash
curl -fsSL https://raw.githubusercontent.com/darshanfct/purgingconsole-releases/main/install-purging-console.sh -o /tmp/install-pc.sh
sudo bash /tmp/install-pc.sh
```

## Update

```bash
sudo purgingconsole --update          # newer version? shows what changed, asks, installs, restarts the service
purgingconsole --update --check       # only tells
sudo purgingconsole --update --yes    # no question (for scripts)
```

`--update` exists from v2.6.11 on. A server on v2.6.10 or older needs the install step above once.

### Automatic update (off by default)

```bash
sudo purgingconsole --set PG_AUTO_UPDATE on          # the service checks once a day and installs newer versions
sudo purgingconsole --set PG_AUTO_UPDATE_AT 04:30    # when (server time; default 03:00)
sudo purgingconsole --set PG_AUTO_UPDATE off         # back to manual
```

Turn it on per server. Every release pushed here then reaches that server within a day.

## Versions

Every release is a tag (`v2.6.6` to `v2.6.11`); what changed is in [CHANGELOG.md](CHANGELOG.md).
