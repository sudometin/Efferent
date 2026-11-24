"""NULLBYTE Ops: SSH server management through Telegram.

Pieces:
  ca        SSH certificate authority: short-lived certs instead of shared keys
  tgauth    Telegram Mini App initData verification (HMAC-SHA256)
  store     server registry (non-secret metadata only), grants, cards, audit log, sessions
  gateway   SSH gateway: WebSocket <-> SSH bridge with host-key pinning, recording, live watchers
  health    probes + alert thresholds + sparkline charts
  record    asciinema casts -> animated GIF (pyte terminal emulator + Pillow)
  knock     TCP port-knock sequences
  web       aiohttp server for the Mini App + WebSocket protocol
"""
