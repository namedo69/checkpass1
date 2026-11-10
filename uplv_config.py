"""Shared fleet defaults, shipped with every worker update."""
MASTER_URL = 'http://160.236.192.49:8761/'
MASTER_TOKEN = ''  # Set MASTER_TOKEN env or mount SECRET_FILE at deployment.
# CheckPass fleet settings retained for reference. These do not change the
# UpLv engine's one-room capacity, sequential login gate or protocol deadlines.
CONCURRENT_CHUNKS = 2
START_GAP = 0
TIMEOUT = 20.0
WORKERS = 15
STATE_DIR = '/state'
POLL_SECONDS = 15
HEARTBEAT_SECONDS = 5
PREPARE_WORKERS = 5
MAX_ROOMS = 5
SECRET_FILE = '/run/secrets/uplv-master-token'
