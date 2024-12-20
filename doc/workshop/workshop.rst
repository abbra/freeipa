.. _workshop:

  Copyright 2015, 2016  Red Hat, Inc.

  This work is licensed under the Creative Commons Attribution 4.0
  International License. To view a copy of this license, visit
  http://creativecommons.org/licenses/by/4.0/.


Introduction
============

FreeIPA_ is a centralised identity management system.  In this
workshop you will learn how to deploy FreeIPA servers and enrol
client machines, define and manage user and service identities, set
up access policies, configure network services to take advantage of
FreeIPA's authentication and authorisation facilities and issue
X.509 certificates for services.

.. _FreeIPA: http://www.freeipa.org/page/Main_Page

.. _curriculum-overview:

Curriculum overview
-------------------

Mandatory:

- :ref:`Unit 1: Installing the FreeIPA server <1-server-install>`
- :ref:`Unit 2: Enrolling client machines <2-client-install>`
- :ref:`Unit 3: User management and Kerberos authentication <3-user-management>`
- :ref:`Unit 4: Host-based access control (HBAC) <4-hbac>`

Optional units—choose the topics that are relevant to you:

- :ref:`Unit 5: Web application authentication and authorisation <5-web-app-authnz>`
- :ref:`Unit 6: Service certificates <6-cert-management>`
- :ref:`Unit 7: Replica installation <7-replica-install>`
- :ref:`Unit 8: Sudo rule management <8-sudorule>`
- :ref:`Unit 9: SELinux User Maps <9-selinux-user-map>`
- :ref:`Unit 10: SSH user and host key management <10-ssh-key-management>`
- :ref:`Unit 11: Kerberos ticket policy <11-kerberos-ticket-policy>`
- :ref:`Unit 12: External IdP support <12-external-idp-support>`

Editing files on VMs
--------------------

Parts of the workshop involve editing files on virtual
machines.  The ``vi`` and GNU ``nano`` editors are available on the
VMs.  If you are not familiar with ``vi`` or you are unsure of what to use, you
should choose ``nano``.


Example commands
----------------

This guide contains many examples of commands.  Some of the commands
should be executed on your host, others on a particular guest VM.
For clarity, commands are annotated with the host on which they are
meant to be executed, as in these examples::

  $ echo "Run it on virtualisation host (no annotation)"

  [server]$ echo "Run it on FreeIPA server"

  [client]$ echo "Run it on IPA-enrolled client"

  ...


Preparation
===========

Some preparation is needed prior to the workshop.  The workshop is
designed to be carried out in an environment built from Podman rootless
containers.  These containers created using ``ipalab-config`` tool and can be
instantiated with ``podman-compose up``.

``ipalab-config`` tool is designed to provide Podman configuration which can be
used together with ``ansible-freeipa`` project. ``ansible-freeipa`` allows to
automate typical FreeIPA operations like deploying a server or a replica and
administrative actions through simple playbooks. The purpose of this workshop
is to learn how to use FreeIPA environment; one can skip manual installation
steps by running an "install cluster" playbook provided by ``ansible-freeipa``
collection. When following this path, first two units of the workshop can be
skipped.


Requirements
------------

For the FreeIPA workshop you will need to:

- Install Podman and ``podman-compose`` tools.

- Use Git to clone the repository containing the workshop data

- Build container image using provided container definition file
  (``lab/containerfile-fedora``)

Please set up these items **prior to the workshop**.  More detailed
instructions follow.


Install and configure Podman
------------------------------

Podman allows to run containers as unprivileged user. The following tutorial
explains how to configure your system for unprivileged (rootless) containers:
https://github.com/containers/podman/blob/main/docs/tutorials/rootless_tutorial.md

Fedora
^^^^^^

On Fedora Podman tools can be installed with ``podman`` and ``podman-compose``
packages::

  $ sudo dnf install -y podman podman-compose

Also ensure you have the latest versions of ``selinux-policy`` and
``selinux-policy-targeted``.

Mac OS X
^^^^^^^^

Install Vagrant for Mac OS X from
https://www.vagrantup.com/downloads.html.

Install VirtualBox 6.1 for **OS X hosts** from
https://www.virtualbox.org/wiki/Downloads.

Install Git from https://git-scm.com/download/mac or via your
preferred package manager.


Debian / Ubuntu
^^^^^^^^^^^^^^^

Install Vagrant, Git and VirtualBox::

  $ sudo apt-get install -y vagrant git
  $ sudo apt-get install -y virtualbox-6.1

If VirtualBox 6.1 was not available in the official packages for
your release, follow the instructions at
https://www.virtualbox.org/wiki/Linux_Downloads to install it.


Windows
^^^^^^^

Install Vagrant via the ``.msi`` available from
https://www.vagrantup.com/downloads.html.

Install VirtualBox for **Windows hosts** from
https://www.virtualbox.org/wiki/Downloads.

You will also need to install an SSH client, and Git.  Git for
Windows also comes with an SSH client so just install Git from
https://git-scm.com/download/win.


Clone this repository
---------------------

This repository contains the ``Vagrantfile`` that is used for the
workshop, which you will need locally.

::

  $ git clone https://github.com/freeipa/freeipa.git
  $ cd freeipa/doc/workshop


Fetch Vagrant box
-----------------

Please fetch the Vagrant box prior to the workshop.  It is > 700MB
so it may not be feasible to download it during the workshop.

::

  $ vagrant box add freeipa/freeipa-workshop


Add hosts file entries
----------------------

*This step is optional.  All units can be completed using the CLI
only.  But if you want to access the FreeIPA Web UI or other web
servers on the VMs from your browser, follow these instructions.*

Add the following entries to your hosts file::

  192.168.33.10   server.ipademo.local
  192.168.33.11   replica.ipademo.local
  192.168.33.20   client.ipademo.local

On Unix systems (including Mac OS X), the hosts file is ``/etc/hosts``
(you need elevated permissions to edit it.)

On Windows, edit ``C:\Windows\System32\system\drivers\etc\hosts`` as
*Administrator*.


Next step
---------

You are ready to begin the workshop.  Continue to
:ref:`Unit 1: Installing the FreeIPA server <1-server-install>`.


After the workshop
------------------

Here are some contact details and resources that may help you after
the workshop is over:

- IRC: ``#freeipa`` and ``#sssd`` (Libera.chat)

- ``freeipa-users@lists.fedorahosted.org`` `mailing list
  <https://lists.fedoraproject.org/archives/list/freeipa-users@lists.fedorahosted.org/>`_

- `How To guides <https://www.freeipa.org/page/HowTos>`_: large
  index of articles about specialised tasks and integrations

- `Troubleshooting guide
  <https://www.freeipa.org/page/Troubleshooting>`_: how to debug
  common problems; how to report bugs

- `Bug tracker <https://pagure.io/freeipa>`_

- Information about the `FreeIPA public demo
  <https://www.freeipa.org/page/Demo>`_ instance

- `Deployment Recommendations
  <https://www.freeipa.org/page/Deployment_Recommendations>`_:
  things to consider when going into production

- `Documentation index
  <https://www.freeipa.org/page/Documentation>`_

- `FreeIPA Planet <http://planet.freeipa.org/>`_: aggregate of
  several FreeIPA and identity-management related blogs

- `GitHub organisation <https://github.com/freeipa>`_.  In addition
  to the `main repository <https://github.com/freeipa/freeipa>`_
  there are various tools, CI-related projects and documentation.

- `Development roadmap <https://www.freeipa.org/page/Roadmap>`_
