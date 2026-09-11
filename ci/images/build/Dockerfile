# freeipa-ci build image: "build the IPA RPMs ourselves" lane.
#
# This is the container that turns a `make srpms` SRPM into binary RPMs
# (design: build the packages using a container with the main image, instead
# of consuming RPMs delivered by a build farm). It is the base image plus
# every BuildRequires of freeipa.spec.in for a Fedora x86_64 full-server
# build (ipatests on, lint/doc/wheels off), baked once so the SRPM build is
# fast and self-contained — no per-build `dnf builddep` against rolling repos.
#
# Building here is self-consistent: the RPM is compiled against whatever
# samba/389-ds/... versions the distro repos currently carry, and the full
# test image is later baked from those same RPMs against the same repo state
# — the class of breakage where a delivered RPM's samba dep no longer resolves
# in the test image (the original "samba 4.24.5 -> 4.24.6" incident) simply
# cannot happen, because build and test share one repo snapshot per build.
#
# The image is built by ci/images/build.sh (alongside base/full). It is only
# needed by the SRPM build path (`build.sh --srpm`); the delivered-RPM path
# (`build.sh --rpms`) never uses it.

ARG BASE=freeipa-ci/base:44
FROM ${BASE}

# Additional COPR repositories to enable before installing anything
# (space-separated OWNER/PROJECT names). Each becomes a dnf repo pointing
# at https://copr.fedorainstantcloud.org/coprs/<owner>/<project>/fedora-
# $releasever/$basearch/. This is the build-lane hook for compiling the SRPM
# against non-distro BuildRequires (or a newer samba/389-ds than the distro
# carries) without changing any preset: channel *creation* is customized
# here, while channel *use* (the preset's abstract `image: freeipa-<channel>`
# reference) stays untouched.
ARG COPR_REPOS=

# Build toolchain. On F44 `rpmbuild` lives in `rpm-build` (split out of
# `rpm`). The autotools + gettext are the spec's unconditional BuildRequires
# (gcc, make, pkgconfig, pkgconf, autoconf, automake, libtool, gettext,
# gettext-devel) that %prep/%build need beyond `dnf builddep`-style BRs.
RUN set -eux; \
    if [ -n "${COPR_REPOS}" ]; then \
        dnf -y install dnf-plugins-core; \
        for repo in ${COPR_REPOS}; do \
            dnf -y copr enable "$repo"; \
        done; \
        dnf makecache; \
    fi; \
    dnf -y install \
        rpm rpm-build make autoconf automake libtool pkgconf pkgconfig \
        gettext gettext-devel \
        gcc diffutils file findutils xz tar \
    && dnf clean all

# freeipa.spec.in BuildRequires (Fedora, x86_64, full server: ONLY_CLIENT=0,
# ipatests on, lint/doc/wheels off, selinux on). Listed by name so the image
# tracks the distro repo state; version-pinned spec requirements (e.g.
# `samba-devel >= X`, `krb5-devel >= Y`) are satisfied by the current
# distro versions, which is exactly the repo snapshot the RPM is built
# against.
RUN dnf -y install \
        # unconditional
        openldap-devel \
        krb5-devel krb5-server \
        libcurl-devel jansson-devel \
        popt-devel gnupg2 \
        nspr-devel openssl-devel \
        libini_config-devel cyrus-sasl-devel \
        python3-devel python3-setuptools python3-argcomplete \
        systemd httpd \
        # ipa_join_xml is on by default (%bcond_with): configure gets
        # --with-ipa-join-xml, which needs xmlrpc-c (not libcurl/jansson,
        # which are the %else branch and are listed below for safety)
        xmlrpc-c-devel \
        # server (ONLY_CLIENT=0)
        389-ds-base-devel \
        samba-devel \
        libtalloc-devel libtevent-devel \
        libuuid-devel libpwquality-devel \
        libsss_idmap-devel libsss_certmap-devel libsss_nss_idmap-devel \
        nodejs npm \
        python3-rjsmin \
        libverto-devel libunistring-devel \
        python3-lesscpy \
        cracklib-dicts \
        # makeapi / makeaci (always)
        python3-cffi python3-dns python3-ldap \
        python3-libsss_nss_idmap python3-netaddr \
        python3-pyasn1 python3-pyasn1-modules python3-six python3-psutil \
        # unit tests (ipatests, ONLY_CLIENT=0)
        libcmocka-devel \
        # SELinux policy
        selinux-policy-devel \
    && dnf clean all

# rpmbuild scratch root (overridden by --define _topdir at build time).
ENV RPM_TOPDIR=/root/rpmbuild
RUN mkdir -p "${RPM_TOPDIR}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
