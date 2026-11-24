# update-bot

This is the bot that keeps my homelab updated and keeps an eye on it. Diun
spots a new container image, the bot pulls the release notes and has Claude
rate how risky the update looks, then posts it to a Matrix room and waits
for me to approve it. Once I do, it takes a Proxmox backup, bumps the
version over SSH, and watches the logs afterward. Over time it picked up a
lot of other jobs too: OS patching and reboots, disk and backup health,
security scans, kernel CVE checks, a daily briefing, and read-only
investigations when something breaks.

The write-up of how it all fits together is on my wiki:

- [update-bot overview](https://wiki.rockbed.xyz/automation/update-bot/overview/)
- [The update pipeline](https://wiki.rockbed.xyz/automation/update-bot/update-pipeline/)
- [What it does on its own](https://wiki.rockbed.xyz/automation/update-bot/autonomous-operations/)
- [Every module, grouped by job](https://wiki.rockbed.xyz/automation/update-bot/modules/)
- [Design rules I'd reuse](https://wiki.rockbed.xyz/automation/patterns/)

## What this repo is

This is a cleaned-up copy of the bot I actually run, shared so people can
see how it's built and borrow from it. It isn't a packaged product, so
expect to read code and change things to fit your own setup.

A few things to know going in:

- **The comments are stripped out.** My private copy has a lot of notes
  about my own network in its comments, so this copy is code only, with a
  one-line summary at the top of each file. The wiki pages above are the
  explanation.
- **Addresses, names and domains are placeholders.** IPs are `192.168.x.x`,
  domains are `example.com`, and people are "the owner". Hostnames like
  `rbd-pmx1` are just my naming scheme, so swap in your own.
- **Some of it is specific to my setup.** A few modules only make sense for
  me (the wedding planning app's access form, my KB site's Cloudflare Access
  rules, Discourse restore), and some assume gear I happen to have
  (FortiGate, Omada, LibreNMS, Synology). Their background loops stay off
  unless you add their section to `config.yaml`, so you can ignore what you
  don't use. `orchestrator.py` imports every module, so leave the files in
  place even if you never turn them on.
- **Some IPs and hostnames are still hardcoded** in a few places
  (`librenms_monitor.py`, `cluster_maintenance.py`,
  `scripts/investigate_wrapper.py`, the `install_*_sudoers.sh` scripts).
  Search for `192.168.` and change them to yours.

## How it's laid out

```text
rbd_update_bot/
  main.py           entrypoint: webhook server, Matrix bot and every background loop
  orchestrator.py   the state machine and all the scheduled loops
  config.py         loads config.yaml + services.yaml, secrets come from .env
  db.py             SQLite state store and audit trail
  webhook.py        Diun webhook receiver (plus the optional public forms)
  classifier.py     Claude calls for risk rating, log review and the briefing
  matrix_bot.py     posting to Matrix and parsing !commands
  executor.py       the actual version bump over SSH, then the log watch
  proxmox.py        Proxmox VE and PBS API clients for the backup step
  cli.py            break-glass approve/abort/status when Matrix is down
  ...               one module per monitor or integration (see the wiki's module page)
scripts/
  investigate_wrapper.py   forced-command SSH target for read-only investigations
  install_*_sudoers.sh     the narrow sudo rules the bot gets on each host
  safe_restart.sh          restarts the bot only when no update is mid-flight
  test_*.py                offline tests and manual checks
systemd/rbd-update-bot.service
config.example.yaml, services.example.yaml, .env.example
```

## Running it

What you need:

- A small VM or LXC of its own with Python 3.12. I keep it separate from my
  management box so its credentials don't share a blast radius with
  anything else.
- An Anthropic API key.
- A Matrix account for the bot and a room for it to post in. Any homeserver
  works.
- Diun watching your containers, with a webhook notifier pointed at the bot.
- An SSH key just for the bot, allowed only on the VMs it manages.
- Proxmox VE and Proxmox Backup Server, with an API token for each scoped to
  backups. The pipeline is built around taking a Proxmox backup before every
  update (`!skip-backup` exists for one-offs, but the config is required).

Setup:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-lock.txt

cp config.example.yaml config.yaml       # Matrix room, admin user IDs, hosts
cp services.example.yaml services.yaml   # one entry per service it manages
cp .env.example .env && chmod 600 .env   # API keys and tokens
```

The sections `config.yaml` can't do without are `webhook`, `matrix`, `llm`,
`database`, `log_watch`, `proxmox` and `pbs`. Everything else is a feature
you can add later, so start small with one or two services in
`services.yaml` and grow it from there.

Run it in the foreground first:

```bash
python -m rbd_update_bot.main          # webhook server + Matrix bot + loops
python -m rbd_update_bot.cli list      # break-glass: list active updates
```

Then point Diun's webhook notifier at `http://<bot-host>:8420/webhook/diun`
and send the `DIUN_WEBHOOK_SECRET` value in an `X-Webhook-Secret` header. If
the secret isn't set, the bot accepts the webhook unauthenticated and only
logs a warning, so set it. Once it behaves, install the systemd unit (edit
the paths and user in it first):

```bash
sudo cp systemd/rbd-update-bot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rbd-update-bot
```

`!help` in the Matrix room lists every command.

## Where my setup differs

- The investigations and security scans run Claude Code on a separate
  management host, reached over SSH with a forced command
  (`scripts/investigate_wrapper.py`). You can skip that whole part and the
  update pipeline still works.
- I talk to a second bot, pass-bot, over a shared Matrix room for mail rules
  and heartbeats (`bot_coordination.py`). pass-bot isn't public, so leave
  the `coordination` section out.
- My services are exposed through Cloudflare Tunnel, and the optional public
  forms (`/report`, the wedding access form) sit behind it. Don't expose
  port 8420 directly to the internet.

## License

MIT, see `LICENSE`.
