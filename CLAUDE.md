# UniFi Gateway for VyOS

The bridge represents a stock VyOS router as a UXG Enterprise in UniFi Network.
VyOS forwards traffic. Enrollment pins the management identity and maps
controller-facing ports to router interfaces.

- Use the setup and source layout in [README.md](README.md).
- Use [docs/coverage.md](docs/coverage.md) as the task tracker. Record the controller,
  router build, packet results and UI evidence for each qualified feature.
- Use [docs/provisioning.md](docs/provisioning.md) for supported intent, ownership,
  read-back and rollback boundaries.
- Run the local checks with `python -m pytest -q` and `ruff check .`.
  Native UI and packet-path acceptance requires a separate device test.
