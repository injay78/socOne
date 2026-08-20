# Native Windows deployment

Runs the full ASP stack as ordinary Windows processes, for hosts where Docker is
not available. The supported deployment is still `deploy/asp-compose`; use this
one only when containers are impossible — for example a Windows VM whose
hypervisor does not expose nested virtualization, so WSL2 and Docker cannot run.

## Layout

Runtime binaries and data live outside the repository, under `ASP_HOME`
(default `C:\Users\trongtd\asp`):

```
asp\
  vendor\      uv, python, pgsql, redis, nginx, node   (portable binaries)
  data\        pgdata, redis, media                    (persistent state)
  logs\        process logs, nginx, postgres, .pids
  certs\       asp.crt, asp.key
  nginx.conf   redis.conf   .secrets.psd1
```

The Python virtualenv stays in the repository at `backend\.venv`, matching the
path used everywhere else in the project.

## Components

| Component | Version | Notes |
| --- | --- | --- |
| Python | 3.14.7 | installed by `uv`, no admin rights needed |
| PostgreSQL | 17.9 | EnterpriseDB binaries-only zip, `pgAdmin` pruned |
| Redis | 8.10.1 | Windows build from `redis-windows/redis-windows` |
| nginx | 1.28.0 | TLS termination, static files, SPA fallback |
| Node | 24.19.0 | build-time only, not part of the running stack |

## Operating the stack

```powershell
.\deploy\native\run_project.ps1            # start everything
.\deploy\native\run_project.ps1 -Status    # per-process state and memory
.\deploy\native\run_project.ps1 -Stop      # stop everything
.\deploy\native\run_project.ps1 -Service infra    # postgres + redis only
.\deploy\native\run_project.ps1 -Service backend  # uvicorn + workers only
.\deploy\native\run_project.ps1 -Service web      # nginx only
```

Reachable at `https://localhost/`. The certificate is self-signed; replace
`certs\asp.crt` and `certs\asp.key` with a real pair and restart nginx.

## Differences from the Compose deployment

- **One uvicorn process** serves both HTTP and WebSocket instead of a gunicorn
  WSGI pool plus a separate ASGI container. Saves roughly 600 MB.
- **Attachments are stored on local disk.** `ASP_FILE_STORAGE=filesystem` in
  `backend\.env` selects `FileSystemStorage`, so no S3-compatible service runs.
  The setting defaults to `s3`, so the Compose deployment is unaffected.
  nginx serves those files from `/media/`.
- **Plain Redis instead of Redis Stack.** The codebase only uses core Redis
  commands, so the RedisJSON and RediSearch modules are not needed.
- **No `upgrade.sh`, `backup.sh` or `doctor.sh`.** Those are Compose-based.
  Upgrades here mean: stop, `git pull`, `uv sync`, `manage.py migrate`,
  `pnpm build`, start.

Note that `python.exe` inside a `uv` virtualenv is a trampoline — the real
interpreter runs as its child process. `run_project.ps1` therefore stops each
service with `taskkill /T` and reports memory across the process tree.

## Trimming resource use

Each worker costs roughly 200 MB. Comment out entries in the `$Workers` array in
`run_project.ps1` for integrations that are not configured yet; `elk_action` and
`trellix_detection` are the usual candidates. PostgreSQL is tuned for a small
host in `data\pgdata\postgresql.conf` (`shared_buffers=128MB`,
`max_connections=50`); raise those on a larger machine.

## Networking on a multi-homed host

This host reaches internal systems over a corporate Ethernet link and the
internet over a guest Wi-Fi link. Two things follow from that.

**Routing.** Wi-Fi wins the default route, and the Ethernet link only carries an
on-link route for its own subnet. Every other internal address therefore leaves
through Wi-Fi and times out. Run once from an elevated PowerShell:

```powershell
.\deploy\native\setup-internal-route.ps1
```

It adds a persistent route for `10.0.0.0/8` through the internal gateway and
verifies that an unbound socket reaches QRadar. Pass `-Prefix`, `-NextHop` or
`-InterfaceAlias` for a different layout, and `-Remove` to undo it. Internal
addresses outside `10.0.0.0/8` need their own route.

**Corporate TLS inspection.** The internal path re-signs public certificates
with `CN=SHB-CA`. Windows trusts that CA, but Python validates against
`certifi`, so every outbound HTTPS call fails with
`CERTIFICATE_VERIFY_FAILED` whenever traffic takes the internal path. The
deployment therefore uses a combined bundle:

```
certs\asp-ca-bundle.pem = certifi + SHB-CA + FortiGate CA + QRadar appliance cert
```

wired in through `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE` in `backend\.env`, and
through `ca_bundle_path` in the QRadar settings. Keep it in place even when the
internet goes out over Wi-Fi, so the stack still works if Wi-Fi drops and
everything falls back to the inspected path.

Rebuild the bundle after any of those certificates is renewed — the QRadar
appliance certificate expires 2026-10-29:

```bash
cat "$(python -c 'import certifi;print(certifi.where())')" certs/corporate-ca.pem certs/qradar-ca.pem > certs/asp-ca-bundle.pem
```

**Remote access.** Once the internal route works, this host can share the
internal network with the rest of the tailnet by acting as a Tailscale subnet
router. See [`tailscale-subnet-router.md`](tailscale-subnet-router.md) — note
that Windows needs OS-level IP forwarding enabled, which the Tailscale docs
omit, and that advertised routes stay inert until approved in the admin
console.
