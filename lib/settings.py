import os

ADMIN_THREADS = int(os.environ.get("ADMIN_THREADS", "4"))
ADMIN_CONN_TIMEOUT = float(os.environ.get("ADMIN_CONN_TIMEOUT", "0.2"))

# support VMs with more than 1 serial port. The port URI which was chosen
# in vcenter when connecting to the vSPC will be stored, and automatically
# appended to device name and device uuid, to identify that particular
# serial port
SUPPORT_MULTI_CONSOLE = os.environ.get("SUPPORT_MULTI_CONSOLE", "false").lower() == "true"

# if >= 1: only allow this many clients per VM
VM_CLIENT_LIMIT = int(os.environ.get("VM_CLIENT_LIMIT", "0"))
