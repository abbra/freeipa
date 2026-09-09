#!/bin/bash
# make-srpms.sh (L1) — produce the freeipa source RPM from a git checkout.
#
# Runs on the machine that owns the freeipa source tree (the control node of
# a CI deployment). Mirrors makerpms.sh's autogen+configure recipe but runs
# `make srpms` instead of `make rpms`: it packages the current git snapshot
# into dist/srpms/freeipa-<version>.src.rpm, which the CI build lane
# (ci/images/build.sh --srpm) compiles into binary RPMs inside the
# freeipa-ci/build image on the runner.
#
# Usage:
#   ci/scripts/make-srpms.sh [configure-args...]
#
# The control machine needs the autotools + rpm (for `rpmbuild -bs`) and the
# distro dev packages the spec references at %prep/%build time are NOT needed
# here: SRPM creation only packages sources and the spec; the heavy BuildRequires
# are satisfied later, inside the build container on the runner.
set -euo pipefail

# This script lives in ci/scripts/; two levels up is the repo root.
pushd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

git submodule update --init --recursive

test ! -x "configure" && autoreconf -i

# Same configure parameters as makerpms.sh, so the SRPM records the same
# host/build triplet and layout a local `make rpms` would use.
test ! -f "Makefile" && ./configure --enable-silent-rules \
    --host=$(rpm -E %{_host}) \
    --build=$(rpm -E %{_build}) \
    --program-prefix=$(rpm -E %{?_program_prefix}) \
    --prefix=$(rpm -E %{_prefix}) \
    --exec-prefix=$(rpm -E %{_exec_prefix}) \
    --bindir=$(rpm -E %{_bindir}) \
    --sbindir=$(rpm -E %{_sbindir}) \
    --sysconfdir=$(rpm -E %{_sysconfdir}) \
    --datadir=$(rpm -E %{_datadir}) \
    --includedir=$(rpm -E %{_includedir}) \
    --libdir=$(rpm -E %{_libdir}) \
    --libexecdir=$(rpm -E %{_libexecdir}) \
    --localstatedir=$(rpm -E %{_localstatedir}) \
    --sharedstatedir=$(rpm -E %{_sharedstatedir}) \
    --mandir=$(rpm -E %{_mandir}) \
    --infodir=$(rpm -E %{_infodir}) \
    "$@"

make srpms

SRPMS="$(find dist/srpms -name '*.src.rpm' | sort | tail -n 1)"
[[ -n "$SRPMS" ]] || { echo "make srpms produced no .src.rpm under dist/srpms" >&2; exit 1; }
echo "SRPM: $(cd "$(dirname "$SRPMS")" && pwd)/$(basename "$SRPMS")"

# Workaround for re-generated *.po noise, same as makerpms.sh.
git checkout po/*.po ||:

popd
