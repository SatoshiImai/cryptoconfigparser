# coding:utf-8
# ---------------------------------------------------------------------------
# author = 'Satoshi Imai'
# credits = ['Satoshi Imai']
# version = "0.9.0"
# ---------------------------------------------------------------------------

import logging
import random
import shutil
import string
import sys
import tempfile
from logging import Logger, StreamHandler
from pathlib import Path
from typing import Generator, Tuple
from unittest.mock import Mock, patch

import aws_encryption_sdk
import pytest

from src.cryptoconfigparser import AESCipher, KMSCryptoConfigParser


@pytest.fixture(scope='session', autouse=True)
def setup_and_teardown(key_path: Path, comp_config_path: Path, config_path: Path,
                       test_string: Tuple[str]):
    # setup

    test_config = f'''
[settings]
key_file={str(key_path)}

[Test]
site=test.site
password={test_string[2]}
'''

    with open(key_path, 'w') as file:
        file.write(test_string[0])
        # end with

    with open(comp_config_path, 'w') as file:
        file.write(test_config)
        # end with

    key_config = f'''
[settings]
key_file={str(key_path)}
key_id=arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222

[Test]
site=test.site
password=deadbeef
'''

    with open(config_path, 'w') as file:
        file.write(key_config)
        # end with

    yield

    # teardown
    # end def


@pytest.fixture(scope='session')
def test_string() -> Generator[Tuple[str], None, None]:

    key = ''.join([random.choice(string.ascii_letters + string.digits)
                   for i in range(32)])
    data = ''.join([random.choice(string.ascii_letters + string.digits)
                    for i in range(50)])

    cipher = AESCipher(key)
    encrypted = cipher.encrypt(data).decode()

    yield (key, data, encrypted)
    # end def


@pytest.fixture(scope='module')
def logger() -> Generator[Logger, None, None]:
    log = logging.getLogger(__name__)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s : %(message)s')
    s_handler = StreamHandler()
    s_handler.setLevel(logging.INFO)
    s_handler.setFormatter(formatter)
    log.addHandler(s_handler)

    yield log
    # end def


@pytest.fixture(scope='session')
def tempdir() -> Generator[Path, None, None]:

    tempdir = Path(tempfile.mkdtemp())
    yield tempdir
    if tempdir.exists():
        shutil.rmtree(tempdir)
        # end if
    # end def


@pytest.fixture(scope='session')
def key_path(tempdir: Path) -> Generator[Path, None, None]:

    yield tempdir.joinpath('test3.key')
    # end def


@pytest.fixture(scope='session')
def comp_config_path(tempdir: Path) -> Generator[Path, None, None]:

    yield tempdir.joinpath('test.3conf')
    # end def


@pytest.fixture(scope='session')
def config_path(tempdir: Path) -> Generator[Path, None, None]:

    yield tempdir.joinpath('kms.conf')
    # end def


@pytest.mark.run(order=10)
def test_init(key_path: Path, comp_config_path: Path, logger: Logger):
    logger.info('init')

    my_config = KMSCryptoConfigParser(comp_config_path, 'utf-8')
    assert my_config.get('settings', 'key_file') == str(key_path)
    # end def


@pytest.mark.run(order=20)
def test_property_config_path(comp_config_path: Path, logger: Logger):
    logger.info('property_comp_config_path')

    my_config = KMSCryptoConfigParser(comp_config_path)

    assert my_config.config_path == str(comp_config_path)
    # end def


@pytest.mark.run(order=30)
def test_property_encoding(comp_config_path: Path, logger: Logger):
    logger.info('property_encoding')

    my_config = KMSCryptoConfigParser(comp_config_path)

    assert my_config.encoding == sys.getdefaultencoding()
    # end def


@pytest.mark.run(order=40)
def test_property_key_file(
        key_path: Path, comp_config_path: Path, logger: Logger):
    logger.info('property_key_file')

    my_config = KMSCryptoConfigParser(comp_config_path)

    assert my_config.key_file == str(key_path)
    # end def


@pytest.mark.run(order=50)
def test_reset_config(key_path: Path, comp_config_path: Path, logger: Logger):
    logger.info('reset_config')

    my_config = KMSCryptoConfigParser(comp_config_path)
    my_config.reset_config(comp_config_path, 'utf-8')

    assert my_config.key_file == str(key_path)
    # end def


@pytest.mark.run(order=60)
def test_load_key_file(key_path: Path, comp_config_path: Path, logger: Logger):
    logger.info('load_key_file')

    my_config = KMSCryptoConfigParser(comp_config_path)
    my_config.load_key_file(key_path)

    assert my_config.key_file == str(key_path)
    # end def


@pytest.mark.run(order=70)
def test_decrypt_with_keyfile(
        test_string: Tuple[str], key_path: Path, comp_config_path: Path, logger: Logger):
    logger.info('decrypt')

    my_config = KMSCryptoConfigParser(comp_config_path)

    assert my_config.decrypt('Test', 'password') == test_string[1]

    my_config.key_file = key_path
    assert my_config.decrypt('Test', 'password') == test_string[1]
    # end def


@pytest.mark.run(order=80)
def test_init_with_kms(
        config_path: Path, logger: Logger):
    logger.info('init_with_kms')

    mock_provider = Mock()
    mock_provider.StrictAwsKmsMasterKeyProvider.return_value = 'dummy'

    mock_client = Mock()
    mock_client.decrypt.return_value = ('dummy', 'dummy')

    with patch.object(aws_encryption_sdk, 'EncryptionSDKClient', return_value=mock_client):
        with patch.object(aws_encryption_sdk, 'StrictAwsKmsMasterKeyProvider', return_value=mock_provider):
            my_config = KMSCryptoConfigParser(
                config_path)
            assert my_config.decrypt('Test', 'password') == 'dummy'
            # end with
        # end with

    assert my_config.config_path == str(config_path)
    # end def


@pytest.mark.run(order=90)
def test_property_key_id(config_path: Path, logger: Logger):
    logger.info('property_key_id')

    my_config = KMSCryptoConfigParser(config_path)
    my_config.key_id = 'dummy'

    assert my_config.key_id == 'dummy'
    # end def


@pytest.mark.run(order=90)
def test_encrypt(
        config_path: Path, logger: Logger):
    logger.info('encrypt')

    mock_provider = Mock()
    mock_provider.StrictAwsKmsMasterKeyProvider.return_value = 'dummy'

    mock_client = Mock()
    mock_client.encrypt.return_value = (b'\xde\xad\xbe\xef', 'dummy')

    with patch.object(aws_encryption_sdk, 'EncryptionSDKClient', return_value=mock_client):
        with patch.object(aws_encryption_sdk, 'StrictAwsKmsMasterKeyProvider', return_value=mock_provider):
            my_config = KMSCryptoConfigParser(
                config_path)
            assert my_config.encrypt('XXX')[0] == 'deadbeef'
            # end with
        # end with

    assert my_config.config_path == str(config_path)
    # end def
