"""Render entrypoint for the normal Checkpass satellite pool."""

import os

os.environ["SATELLITE_SERVICE_TYPE"] = "normal"

from satellite_worker import main


if __name__ == "__main__":
    raise SystemExit(main())
