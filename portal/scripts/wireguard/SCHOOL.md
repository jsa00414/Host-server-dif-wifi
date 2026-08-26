# WireGuard on school / campus Wi‑Fi

Schools often interfere with WireGuard on UDP **5000**. This host also accepts WireGuard on UDP **443** (redirected to 5000).

## Flint / GL.iNet client settings

1. Open the WireGuard client that connects to the VPS.
2. Set **Endpoint** to `74.208.76.213:443` (was `:5000`).
3. Set **MTU** to `1280` (school paths are often tighter than home).
4. Keep **Persistent Keepalive** at `25`.
5. Save, disable, then enable the tunnel.

## If the tunnel shows up but Files / NAS do not

The VPS can see handshakes from the school network even when LAN devices are missing. The Buffalo NAS must be on the **same LAN as the Flint** (plugged into the router at school). A NAS left at home will not be reachable through this tunnel.
