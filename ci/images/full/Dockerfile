# freeipa-ci full image (A2): the CI test lane.
#
# Base image + a dev-build of FreeIPA (one git SHA). The IPA packages are
# installed from local RPMs (built by the rpmbuild job for that SHA);
# everything else resolves from the distribution repos.
#
# Repo pinning (design layer 2): the IPA build was tested against a frozen
# repo state. When a dependency has since moved (e.g. samba 4.24.5 -> 4.24.6
# breaking freeipa-server-trust-ad's Provides requirement), pin it with
# PIN_SPECS so the IPA RPMs resolve against the tested versions:
#
#   --build-arg PIN_SPECS="samba-4.24.5-1.fc44 samba-libs-4.24.5-1.fc44"
#
# Pinned versions are installed first; dnf then leaves them in place while
# resolving the IPA RPMs. Without a pin the image is best-effort against the
# current repos.

ARG BASE=freeipa-ci/base:44
FROM ${BASE}

# Space-separated NVR specs to install before the IPA RPMs (see above).
ARG PIN_SPECS=

# The build context is prepared by ci/images/build.sh: it contains rpms/
# with the selected IPA RPMs for the target SHA.
COPY rpms/ /root/rpms/

RUN set -eux; \
    if [ -n "${PIN_SPECS}" ]; then \
        dnf -y install ${PIN_SPECS}; \
    fi; \
    dnf -y install /root/rpms/*.rpm; \
    rm -rf /root/rpms /var/cache/dnf/*

# Samba lane (design §3.3): freeipa-server-trust-ad and freeipa-client-samba
# come from the IPA RPM set; their samba-* dependencies resolve from the
# distro repos (4.24.x). python3-samba provides the server-side python
# bindings imported by the xmlrpc idrange tests; sudo is needed by the
# client-side sudo job.
RUN dnf -y install python3-samba sudo && rm -rf /var/cache/dnf/*
