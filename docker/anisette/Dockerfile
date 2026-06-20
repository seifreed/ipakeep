# ipakeep anisette server
#
# AOSKit (which produces Apple's `X-Apple-I-MD*` provisioning/OTP tokens) only
# exists on macOS. Windows and Linux therefore cannot generate valid Anisette
# data locally, so ipakeep talks to an anisette server over HTTP instead.
#
# This image wraps the upstream `anisette-v3-server` (Dadoum/Provision), which
# implements Apple's provisioning protocol. ipakeep launches it automatically on
# non-macOS hosts, or you can run it yourself (see docker-compose.yml).
#
# Build:
#   docker build -t ipakeep-anisette docker/anisette
# Run:
#   docker run -d --name ipakeep-anisette -p 6969:6969 \
#       -v ipakeep-anisette-data:/home/Alcoholic/.config/anisette-v3/lib/ \
#       ipakeep-anisette
#
# Pin to a digest in production instead of a moving tag.
FROM dadoum/anisette-v3-server:latest

# gsa.apple.com (used during device provisioning) chains to Apple's own
# "Apple Root CA", which the base Debian image does NOT trust. Without it the
# server's provisioning TLS handshake fails and it crash-loops with a misleading
# "Timeout receiving data". Install the root so provisioning succeeds.
# (Same cert ipakeep bundles in src/infrastructure/http/apple_root_ca.pem.)
#
# The server downloads its Apple provisioning library (from the Apple Music APK)
# itself on first run; that is upstream's responsibility, not ours.
USER root
COPY apple_root_ca.pem /usr/local/share/ca-certificates/apple-root-ca.crt
RUN update-ca-certificates
USER Alcoholic

# The provisioning state (device identity) must persist across restarts;
# re-provisioning on every start can trip Apple rate limiting.
VOLUME ["/home/Alcoholic/.config/anisette-v3/lib/"]

# anisette-v3-server listens on 6969.
EXPOSE 6969
