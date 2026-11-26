#!/usr/bin/env python3
"""Build the stock VyOS inspection kit from the checked-out source."""

import argparse
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
MODULES = (
    "eve_source", "notify_capture", "notify_observation", "notify_runtime",
    "supervisor", "suricata", "vyos_command", "vyos_control",
    "vyos_eve_feed", "vyos_install", "vyos_queue", "vyos_readback",
)


def build(output):
    sources = {f"inspection/{name}.py": (ROOT / f"inspection/{name}.py").read_bytes()
               for name in MODULES}
    sources["inspection/__init__.py"] = b""
    sources["__main__.py"] = b"from inspection.vyos_install import main\nraise SystemExit(main())\n"
    with output.open("xb") as stream:
        stream.write(b"#!/usr/bin/python3 -I\n")
        with ZipFile(stream, "w") as archive:
            for path, content in sorted(sources.items()):
                archive.writestr(ZipInfo(path), content, compress_type=ZIP_DEFLATED)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="Path for the new router kit archive")
    build(parser.parse_args().output)
