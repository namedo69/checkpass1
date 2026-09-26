"""Render entrypoint for the dedicated VVIP Checkpass satellite pool."""

import os

os.environ["SATELLITE_SERVICE_TYPE"] = "vvip"

from satellite_worker import main


if __name__ == "__main__":
    raise SystemExit(main())
