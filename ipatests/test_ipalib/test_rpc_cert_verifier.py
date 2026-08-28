#
# Copyright (C) 2026 FreeIPA Contributors, see 'COPYING' for license.
#
"""Unit tests for the cert_verifier hook in the RPC transport
(SSLTransport.make_connection in ipalib/rpc.py).

When the server certificate cannot be verified against the local CA
bundle, a caller may install a cert_verifier on the request context;
the transport then asks it for an alternative trust anchor (e.g. the
peer's CA chain fetched over an unverified connection) and retries the
connection once with full verification against the returned anchor.
This is what the full-credentials IPA-to-IPA trust flow uses to
bootstrap trust in the remote deployment's CA (trust on first use).
"""
from __future__ import absolute_import

from ssl import SSLError
from unittest import mock

import pytest

from ipalib import errors, rpc


def _make_transport():
    """A bare SSLTransport whose host lookup is mocked out."""
    transport = rpc.SSLTransport.__new__(rpc.SSLTransport)
    transport._connection = None
    transport._extra_headers = []
    transport.get_host_info = mock.Mock(
        return_value=('b.example.test', [], None))
    transport.close = mock.Mock()
    return transport


class TestMakeConnectionCertVerifier:
    def test_ssl_error_without_verifier_raises_network_error(self):
        transport = _make_transport()
        bad = mock.Mock()
        bad.connect.side_effect = SSLError('certificate verify failed')

        with mock.patch.object(rpc, 'create_https_connection',
                               return_value=bad), \
             mock.patch.object(rpc.context, 'cert_verifier', None,
                               create=True):
            with pytest.raises(errors.NetworkError):
                transport.make_connection('b.example.test')

    def test_verifier_anchor_retries_verification(self):
        transport = _make_transport()
        bad = mock.Mock()
        bad.connect.side_effect = SSLError('certificate verify failed')
        good = mock.Mock()

        verifier = mock.Mock(return_value='VERIFIER')
        with mock.patch.object(rpc, 'create_https_connection',
                               side_effect=[bad, good]) as chc, \
             mock.patch.object(rpc, 'api', mock.MagicMock()), \
             mock.patch.object(rpc.context, 'cert_verifier', verifier,
                               create=True):
            conn = transport.make_connection('b.example.test')

        assert conn is good
        verifier.assert_called_once_with('b.example.test')
        # the first connection used the local anchor, the retry used
        # the anchor the verifier provided
        assert chc.call_args_list[0][0][2] is None
        assert chc.call_args_list[1][0][2] == 'VERIFIER'
        bad.close.assert_called_once_with()
        good.connect.assert_called_once_with()

    def test_verifier_refusing_to_establish_trust_fails(self):
        transport = _make_transport()
        bad = mock.Mock()
        bad.connect.side_effect = SSLError('certificate verify failed')

        with mock.patch.object(rpc, 'create_https_connection',
                               return_value=bad), \
             mock.patch.object(rpc, 'api', mock.MagicMock()), \
             mock.patch.object(rpc.context, 'cert_verifier',
                               mock.Mock(return_value=None),
                               create=True):
            with pytest.raises(errors.NetworkError):
                transport.make_connection('b.example.test')

    def test_retry_failure_raises_network_error(self):
        transport = _make_transport()
        bad = mock.Mock()
        bad.connect.side_effect = SSLError('certificate verify failed')
        still_bad = mock.Mock()
        still_bad.connect.side_effect = SSLError(
            'certificate verify failed')

        with mock.patch.object(rpc, 'create_https_connection',
                               side_effect=[bad, still_bad]), \
             mock.patch.object(rpc, 'api', mock.MagicMock()), \
             mock.patch.object(rpc.context, 'cert_verifier',
                               mock.Mock(return_value='/some/ca.pem'),
                               create=True):
            with pytest.raises(errors.NetworkError):
                transport.make_connection('b.example.test')
        still_bad.close.assert_called_once_with()

    def test_plain_socket_error_still_raises_network_error(self):
        import socket
        transport = _make_transport()
        bad = mock.Mock()
        bad.connect.side_effect = socket.error('refused')

        with mock.patch.object(rpc, 'create_https_connection',
                               return_value=bad), \
             mock.patch.object(rpc.context, 'cert_verifier', None,
                               create=True):
            with pytest.raises(errors.NetworkError):
                transport.make_connection('b.example.test')
