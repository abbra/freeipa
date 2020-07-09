#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

from __future__ import print_function, absolute_import

import logging

from ipaplatform.paths import paths
from ipapython.install.common import Installable, Interactive
from ipapython.install.core import group, knob, Composite
from ipapython.install import typing
from ipaserver.install import ca, dsinstance, gcinstance
from ipaserver.install import installutils
from ipapython import ipautil

logger = logging.getLogger(__name__)


@group
class GCInstallInterface(Installable,
                         Interactive,
                         Composite):
    """
    Interface for the Global Catalog installer
    """
    description = "Global Catalog"

    gc_cert_files = knob(
        # pylint: disable=invalid-sequence-index
        typing.List[str], None,
        description=("File containing the Global Catalog SSL certificate and "
                     "private key"),
        cli_names='--gc-cert-file',
        cli_metavar='FILE',
    )

    gc_pin = knob(
        str, None,
        sensitive=True,
        description="The password to unlock the Global Catalog private key",
        cli_deprecated_names='--gc_pin',
        cli_metavar='PIN',
    )


def install_check(api, installer):
    if gcinstance.is_gc_configured():
        installer._setup_gc = False
        return
    installer._setup_gc = True

    options = installer

    gc_pkcs12_file = None
    gc_pkcs12_info = None

    # Checks for valid configuration

    # Ask for required options in non-interactive mode
    # If a cert file is provided, PIN is required
    if options.gc_cert_files:
        if options.gc_pin is None and not options.unattended:
            options.gc_pin = installutils.read_password(
                "Enter Global Catalog private key unlock",
                confirm=False, validate=False, retry=False)
        if options.gc_pin is None:
            raise RuntimeError("You must specify --gc-pin with --gc-cert-file")

        gc_pkcs12_file, gc_pin, _gc_ca_cert = installutils.load_pkcs12(
            cert_files=options.gc_cert_files,
            key_password=options.gc_pin,
            key_nickname=None,
            ca_cert_files=[paths.IPA_CA_CRT])
        gc_pkcs12_info = (gc_pkcs12_file.name, gc_pin)

    installer._gc_pkcs12_info = gc_pkcs12_info
    installer._gc_pkcs12_file = gc_pkcs12_file


def install(api, fstore, installer):
    options = installer
    if not options._setup_gc:
        print("Global Catalog already installed, skipping")
        return

    gc_pkcs12_info = installer._gc_pkcs12_info

    domainlevel = api.Command['domainlevel_get']()['result']
    subject_base = dsinstance.DsInstance().find_subject_base()
    ca_subject = ca.lookup_ca_subject(api, subject_base)
    # Generate a random DM password for GC
    gc_password = ipautil.ipa_generate_password()

    if installer.gc_cert_files:
        gc = gcinstance.GCInstance(fstore=fstore, domainlevel=domainlevel)
        installer._gc = gc
        gc.create_instance(api.env.realm, api.env.host, api.env.domain,
                           gc_password, gc_pkcs12_info,
                           subject_base=subject_base,
                           ca_subject=ca_subject)
    else:
        gc = gcinstance.GCInstance(fstore=fstore, domainlevel=domainlevel)
        installer._gc = gc
        gc.create_instance(api.env.realm, api.env.host, api.env.domain,
                           gc_password,
                           subject_base=subject_base,
                           ca_subject=ca_subject)

    gc.apply_updates()

    gcsyncd = gcinstance.GCSyncInstance(fstore=fstore)
    installer._gcsyncd = gcsyncd
    gcsyncd.create_instance(api.env.realm, api.env.host)


def uninstall_check():
    if not gcinstance.is_gc_configured():
        print("WARNING:\nGlobal Catalog is not configured on this system.")


def uninstall(fstore):
    gcinstance.GCSyncInstance(fstore=fstore).uninstall()
    gcinstance.GCInstance(fstore=fstore).uninstall()
