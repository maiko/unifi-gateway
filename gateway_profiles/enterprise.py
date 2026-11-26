"""UniFi identity of the VyOS-backed Gateway Enterprise."""

MODEL = "UXGENT"
DISPLAY_NAME = "Gateway Enterprise"
FIRMWARE = "6.0.17"


def require_enterprise(config):
    if (config.get("gateway", "device", fallback="") != MODEL
            or config.get("gateway", "platform", fallback="").strip().lower() != "vyos"):
        raise ValueError("Gateway configuration requires model UXGENT and platform vyos")
