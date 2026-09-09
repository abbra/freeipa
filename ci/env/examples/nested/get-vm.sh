#!/bin/sh
# Example "get a VM" script for the freeipa-env nested provider
# (provider: nested, vm.backend: command).
#
# The nested provider invokes this with a single argument = the number of
# VMs to provision, and expects one ssh target per line on stdout:
#
#     user@host[:port]
#
# Replace the body with your cloud API call (provision, wait for ready,
# print the ssh target). This example reads the target from $NESTED_VM_HOST
# so you can try the nested provider against any pre-existing ssh-reachable
# host without a real cloud.

count="${1:-1}"
host="${NESTED_VM_HOST:-}"
if [ -z "$host" ]; then
    echo "get-vm.sh: set NESTED_VM_HOST=user@host (or replace this script" \
         "with your cloud API call)" >&2
    exit 1
fi
# provision `count` VMs (this example returns the same host `count` times)
i=1
while [ "$i" -le "$count" ]; do
    echo "$host"
    i=$((i + 1))
done
