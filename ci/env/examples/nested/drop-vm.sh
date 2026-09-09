#!/bin/sh
# Example "deprovision" script for the freeipa-env nested provider
# (provider: nested, vm.backend: command).
#
# The nested provider invokes this once per VM being released, passing the
# VM id (or its user@host target) as $1. Replace the body with your cloud
# API delete/terminate call.

echo "drop-vm.sh: deprovisioning $1 (no-op example)"
