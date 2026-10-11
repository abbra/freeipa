#
# Copyright (C) 2022  FreeIPA Contributors see COPYING for license
#

import pytest

from ipalib import errors
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test, raises_exact
from ipatests.test_xmlrpc.tracker.passkey_plugin import PasskeyconfigTracker
from ipatests.test_xmlrpc.tracker.user_plugin import UserTracker
from ipatests.test_xmlrpc.tracker.stageuser_plugin import StageUserTracker


@pytest.fixture(scope='class')
def passkey_config(request, xmlrpc_setup):
    tracker = PasskeyconfigTracker()
    return tracker.make_fixture(request)


class TestPasskeyconfig(XMLRPC_test):
    @pytest.mark.parametrize("userverification", [False, True])
    def test_config_mod(self, passkey_config, userverification):
        """
        Test the passkeyconfig-mod CLI with possible values for
        --require-user-verification parameter.
        """
        passkey_config.update(
            {'iparequireuserverification': userverification},
            {'iparequireuserverification': [userverification]}
        )

    def test_config_mod_invalid_requireverif(self, passkey_config):
        """
        Test the passkeyconfig-mod CLI with invalid values for
        --require-user-verification parameter.
        """
        cmd = passkey_config.make_update_command(
            updates={'iparequireuserverification': 'Invalid'}
        )

        with pytest.raises(errors.ConversionError):
            cmd()

    def test_config_show(self, passkey_config):
        """
        Test the passkeyconfig-show command.
        """
        passkey_config.retrieve()


PASSKEY_USER = 'passkeyuser'
PASSKEY_KEY = ("passkey:"
               "E8Zay6UJm6PG/GcQnej2WMyUrWqijejBCqPWFX6THPrx"
               "ab01Z59bUgutipn5MIk8/zMU6RBlp7jSbkNJsZtomw==,"
               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgryfr3YR"
               "M9OVdWHEDrbvcSyT5D0b/8Ks+fMp8MM0BXV/FOo436ZP"
               "jUqSU+2LOXVGdKkJU1XBiwl+n/X+vGD1vw==")
PASSKEY_DISCOVERABLEKEY = (
    "passkey:"
    "pP2z07ygq36HkNabd79ki9H6rfYEIVdluSHjY1YykUbVECXJ3ZDZ3n1EZ9G8HhMv,"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpP2z07ygq36HkNabd1H9Knqqghjv"
    "vhlW0+FcNzOoXP+49tC/Ee2TbjC3x2dIzJEBFi7iDPSc+OCM+WmD1AfPLQ==,"
    "P6GjSqAo+RoQRJhGFA3lKcvtpKTGETjCdtVIyLX0KcY=")
PASSKEY_ES384_KEY = (
    "passkey:HTplwdXPJromNnlHpmee1L+EIbO6p2DDPGsOTRAE7e+VUSKxM9c9vWJH"
    "Qi+Kz2zL1XD2CyvJvkkr2kXbz0131g==,MHYwEAYHKoZIzj0CAQYFK4EEACIDYgA"
    "E91QgrnzfNoB15hts8qJsA6Sq68en5x0nctDDI9bTdLupgtkqQi+dfbdq2e8zUhC"
    "DgXMBftNwB9v2MBuq45LP6KigC+0Y8Su9Cp52sXFucvjTyVWHfjTDAM7kUCearjL"
    "z")
PASSKEY_MLDSA44_KEY_VALUE = (
    "passkey:A/5bNARgPHEWj2gqQ6PxCOC0YOnmcX8tOrpNG0c/uTHDaSwJAKgL+0PR"
    "yb8L4DeMs2b7rA7c4n49En1O3rq3YA==,MIIFMjALBglghkgBZQMEAxEDggUhAPI"
    "iE5qSY95Fb2k/beRbx4ZJZ48TtsOWjh3BZ7dXcczrxUtC0N+nPUarjyW//wJ7Pav"
    "eWu4wcZyib/EhZl5z8hN8/8ScRy682utLOwZHpFe2QsGtxl0/KUsa9/xRsOCwhIP"
    "dl4YYOTjXbxMUiTj6fj34ksyjniXK/TPUHSWHKK2/PXaDMRUmEmPuVrz5t6k/rjU"
    "5iYIsBYkRlA8uc8/05vrQ9EF2H+kQuVgjk+vrDDQFKXWqBpPC/4ouiNgcwZeeUcq"
    "abe9qusWeFYjlc7OTPojtVOjy8z/Wbr7ks3qhF+1SIrviPGphP7laiJb7VuFYZ1o"
    "uXNN1STiQR+lhWwf5wsqI9u8H+ddvdHtfa/ONcODzchfFmmvGRylZsupWq+9x+n4"
    "kYecOn0C8R+JT8kBPYa9ow7DgzjY5c8wwg57vHqwetl975XVT+F74edbvbee/55c"
    "PS9hzAxmWwvcE8Z6ibHPnRft8gPPhZBXgl2IK8MGPIiHpjixOVU5LnPL8YpDNbx3"
    "yAqYO86sv5qs1FmBSD1TWAiV4rMQyNYpkijCLEMXKxoCJUd3IVKR7ycjzG/2IBE2"
    "kwV3QnHBUjyYtaS7uvUnkb6gSiyyc49NfuL4M2SRDS+TMFeWVswUFjlLemLho7kj"
    "dnU7O4nsmuGKZg6CyUnGlEYYZQ2QbvHJdswicIUB2eYQ7ufVZa7hfM7wTZiDQpsH"
    "uQ775p/mw4MaLJ5S1UzJtH/wi0sW29jRrWHw+HtcTC4/Tq0k2SyGs2g9dhQW6jSz"
    "QjW9UZPJdwc8M22HpsqQLwV4VTcuLHoWezp4lVk+siqrB2pU33OqLrbalr7XJCDp"
    "1k88bxIp3PhJqs5ynT49iXGEbyZUA41c5J8SeG5QWFUNTn/GhPkFUr0up7pAPvBm"
    "QzVKim9sb9ntEN7ePV8Io8dInauPl4FTbOkqt2fiDXykj/GEhcTaCGEbqV7BpbZl"
    "jTsNdh8ruhnGbPA11rzDNhESh6PpEdUqME8hp2fHKmqcZF14Jze6mlM1MYdU9C42"
    "ZmS5tjI33OiI4Kxj9AfpzLVEUY2Gw10yzlmIxhUR95G0GMR6u4gpE6nUcDUhcyMB"
    "plNh6f2pWt/ubuveJPcwVYSoqx/VAx6ZNT3oquXdf05RpER8WMzjc9Q6AWFruKnh"
    "bGxI8Aox9aFKmKFT16Hb0PiWrU6ADZgyyGLLSqY91p93uPaYEpp8GGj5bWqND9Hr"
    "AUi3jmzP/rDFdFF+MvsmA13OU/kHVbjhj935nSDuXskl7YCuGzMvj+ZXC4nD7iMV"
    "RUHV0dI2GGOnoG1i2YfYcxQg4uqLPFe/uN9FnEoPxBNZ3L8G93mdLc9KglK+084q"
    "CV6AQD7RIlJDK0Ds8900ieuvc9BfAJmQQgbdTxMJUjYwed8LzqwvLFHtJ+X1Wi5s"
    "+YnjtBq9oPPEaOySjRn25LZ0fszagPL46W98fPMs68tj69rx6XNo2XLcuRGxMqPE"
    "tTHmLYeyatDuqWh8loC9dBflRwC6kEO/1HuHhCKE5eyM61qhX6XsCMQ2LwUY1zRw"
    "t8MqjrwSlxU5k41NOZfa/yBCXCZmGtnBu2L56D1EyskqtvjAR4AxvFHslPyngA0I"
    "PABbm/9eSFSgVTteSD0IX8SZuX2ZFJDWqnt3Tmfdv4qbAt5C+Dycq9WjdzIyPgB7"
    "jE2coY36IbYwVvgSiRT4NAmOOjjAD/z2jbsO7Hh5Vao3uGNYSxQ0T5intjlt6Oah"
    "K2hQd9i5BrI1wcsfXJpU=")


def _has_mldsa():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa
    except ImportError:
        return False
    return True


# Storing an ML-DSA public key requires python-cryptography with ML-DSA
# support on the server.
PASSKEY_MLDSA44_KEY = pytest.param(
    PASSKEY_MLDSA44_KEY_VALUE,
    marks=pytest.mark.skipif(not _has_mldsa(),
                             reason="python-cryptography lacks ML-DSA"))
PASSKEY_KEYS = [PASSKEY_KEY, PASSKEY_DISCOVERABLEKEY, PASSKEY_ES384_KEY,
                PASSKEY_MLDSA44_KEY]


@pytest.fixture
def passkeyuser(request):
    user = UserTracker(PASSKEY_USER, 'passkey', 'user')
    return user.make_fixture(request)


class TestAddRemovePasskey(XMLRPC_test):
    @pytest.mark.parametrize("key", PASSKEY_KEYS)
    def test_add_passkey(self, passkeyuser,key):
        passkeyuser.ensure_exists()
        passkeyuser.add_passkey(ipapasskey=key)
        passkeyuser.ensure_missing()

    @pytest.mark.parametrize("key", PASSKEY_KEYS)
    def test_remove_passkey(self, passkeyuser, key):
        passkeyuser.ensure_exists()
        passkeyuser.add_passkey(ipapasskey=key)
        passkeyuser.remove_passkey(ipapasskey=key)

    @pytest.mark.parametrize("key", ['wrongval', 'passkey:123', 'passkey,123'])
    def test_add_passkey_invalid(self, passkeyuser, key):
        passkeyuser.ensure_exists()
        cmd = passkeyuser.make_command('user_add_passkey',
                                       passkeyuser.name)
        with raises_exact(errors.ValidationError(
                name='passkey',
                error='"{}" is not a valid passkey mapping'.format(key))):
            cmd(key)

    def test_add_passkey_invalidid(self, passkeyuser):
        passkeyuser.ensure_exists()
        key = ("passkey:123,"
               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgryfr3YRM9OVdWHEDrbvc"
               "SyT5D0b/8Ks+fMp8MM0BXV/FOo436ZPjUqSU+2LOXVGdKkJU1XBiwl+n/X"
               "+vGD1vw==")
        msg = '"{}" is not a valid passkey mapping, invalid id'
        cmd = passkeyuser.make_command('user_add_passkey',
                                       passkeyuser.name)
        with raises_exact(errors.ValidationError(
                name='passkey',
                error=msg.format(key))):
            cmd(key)

    def test_add_passkey_invalidpem(self, passkeyuser):
        passkeyuser.ensure_exists()
        key = ("passkey:"
               "E8Zay6UJm6PG/GcQnej2WMyUrWqijejBCqPWFX6THPrxab01Z59bUguti"
               "pn5MIk8/zMU6RBlp7jSbkNJsZtomw==,"
               "wrongpem")
        msg = '"{}" is not a valid passkey mapping, invalid key'
        cmd = passkeyuser.make_command('user_add_passkey',
                                       passkeyuser.name)
        with raises_exact(errors.ValidationError(
                name='passkey',
                error=msg.format(key))):
            cmd(key)

    def test_add_passkey_invaliduserid(self, passkeyuser):
        passkeyuser.ensure_exists()
        key = ("passkey:"
               "E8Zay6UJm6PG/GcQnej2WMyUrWqijejBCqPWFX6THPrxab01Z59bUguti"
               "pn5MIk8/zMU6RBlp7jSbkNJsZtomw==,"
               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgryfr3YRM9OVdWHEDrbvc"
               "SyT5D0b/8Ks+fMp8MM0BXV/FOo436ZPjUqSU+2LOXVGdKkJU1XBiwl+n/X"
               "+vGD1vw==,"
               "wrongid")
        msg = '"{}" is not a valid passkey mapping, invalid userid'
        cmd = passkeyuser.make_command('user_add_passkey',
                                       passkeyuser.name)
        with raises_exact(errors.ValidationError(
                name='passkey',
                error=msg.format(key))):
            cmd(key)


STAGEPASSKEY_USER = 'stagepasskeyuser'


@pytest.fixture
def stagepasskeyuser(request):
    user = StageUserTracker(STAGEPASSKEY_USER, 'stagepasskey', 'user')
    return user.make_fixture(request)


class TestStageAddRemovePassKey(XMLRPC_test):
    def test_add_passkey(self, stagepasskeyuser):
        stagepasskeyuser.ensure_exists()
        stagepasskeyuser.add_passkey(ipapasskey=PASSKEY_KEY)
        stagepasskeyuser.ensure_missing()

    def test_remove_passkey(self, stagepasskeyuser):
        stagepasskeyuser.ensure_exists()
        stagepasskeyuser.add_passkey(ipapasskey=PASSKEY_KEY)
        stagepasskeyuser.remove_passkey(ipapasskey=PASSKEY_KEY)

    @pytest.mark.parametrize("key", ['wrongval', 'passkey:123', 'passkey,123'])
    def test_add_passkey_invalid(self, stagepasskeyuser, key):
        stagepasskeyuser.ensure_exists()
        cmd = stagepasskeyuser.make_command('user_add_passkey',
                                            stagepasskeyuser.name)
        with raises_exact(errors.ValidationError(
                name='passkey',
                error='"{}" is not a valid passkey mapping'.format(key))):
            cmd(key)
