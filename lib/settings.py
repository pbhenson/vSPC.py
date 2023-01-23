import os

ADMIN_THREADS = int(os.environ.get("ADMIN_THREADS", "4"))
ADMIN_CONN_TIMEOUT = float(os.environ.get("ADMIN_CONN_TIMEOUT", "0.2"))
