# Anisette server (Windows / Linux support)

Apple's GrandSlam login requires **Anisette** data — the `X-Apple-I-MD` /
`X-Apple-I-MD-M` OTP tokens plus a coherent device identity. These are produced
by `AOSKit.framework`, which **only exists on macOS**.

On Windows and Linux ipakeep cannot generate valid tokens locally, so it uses an
**anisette server** (here, the upstream `anisette-v3-server`) running in Docker
and fetches the tokens over HTTP.

## How ipakeep uses it

When ipakeep needs Anisette data it resolves a provider in this order:

1. **`IPAKEEP_ANISETTE_URL`** — if set, fetch from that URL (any reachable
   anisette server, local or remote).
2. **macOS** — generate locally via AOSKit (no Docker needed).
3. **Windows / Linux** — automatically ensure a local container named
   `ipakeep-anisette` is running on `http://127.0.0.1:6969` (starting or
   `docker run`-ing it if needed), then fetch from it.

So on Windows/Linux you normally need **nothing except Docker installed** — the
first login will pull the image and launch the container automatically.

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `IPAKEEP_ANISETTE_URL` | Use an explicit anisette server and skip auto-launch | unset |
| `IPAKEEP_ANISETTE_IMAGE` | Image used for auto-launch | `dadoum/anisette-v3-server:latest` |

## Running it yourself

Build and run this repo's image:

```bash
docker build -t ipakeep-anisette docker/anisette
docker run -d --name ipakeep-anisette -p 6969:6969 \
    -v ipakeep-anisette-data:/home/Alcoholic/.config/anisette-v3/lib/ \
    ipakeep-anisette
```

Or with Compose:

```bash
docker compose -f docker/anisette/docker-compose.yml up -d
export IPAKEEP_ANISETTE_URL=http://localhost:6969
```

To point ipakeep at the image you built instead of the public one during
auto-launch:

```bash
export IPAKEEP_ANISETTE_IMAGE=ipakeep-anisette
```

## Notes

- The named volume persists the server's device provisioning state. Keep it —
  re-provisioning on every start can trigger Apple rate limiting.
- macOS users can also use a remote server by setting `IPAKEEP_ANISETTE_URL`.
