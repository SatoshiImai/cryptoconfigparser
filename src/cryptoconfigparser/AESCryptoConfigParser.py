# coding:utf-8
# ---------------------------------------------------------------------------
# __author__ = 'Satoshi Imai'
# __credits__ = ['Satoshi Imai']
# __version__ = '0.9.0'
# ---------------------------------------------------------------------------

import base64
import codecs
import sys
from configparser import RawConfigParser
from pathlib import Path

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Padding


class AESCryptoConfigParser(RawConfigParser):

    SETTING_SECTION_KEY = 'settings'
    KEYFILE_OPTION_KEY = 'key_file'

    def __init__(self, config_path: str = None, encoding: str = None):
        super(AESCryptoConfigParser, self).__init__()

        self.__cipher = None
        self.__encoding = sys.getdefaultencoding()
        if encoding:
            self.__encoding = encoding
            # end if

        if config_path:
            if isinstance(config_path, Path):
                config_path = str(config_path)
                # end if

            self.reset_config(config_path, self.__encoding)

            if self.has_option(self.SETTING_SECTION_KEY,
                               self.KEYFILE_OPTION_KEY):
                # load key
                self.load_key_file(
                    self.get(
                        self.SETTING_SECTION_KEY,
                        self.KEYFILE_OPTION_KEY))
                # end if
            # end if
        # end def

    def get_config_path(self):
        return self.__config_path
        # end def

    config_path = property(get_config_path)

    def get_encoding(self):
        return self.__encoding
        # end def

    encoding = property(get_encoding)

    def get_key_file(self):
        return self.__key_file
        # end def

    def set_key_file(self, value: str):
        self.__key_file = value
        self.__cipher = None
        # end def

    key_file = property(get_key_file, set_key_file)

    def reset_config(self, config_path: str = None, encoding: str = None):
        if config_path:
            self.__config_path = config_path
            # end if
        if encoding:
            self.__encoding = encoding
            # end if

        super(
            AESCryptoConfigParser,
            self).read(
            self.config_path,
            self.encoding)
        # end def

    def load_key_file(self, key_file_path: str = None):
        if key_file_path:
            if isinstance(key_file_path, Path):
                key_file_path = str(key_file_path)
                # end if

            self.key_file = key_file_path
            # end if

        with codecs.open(self.key_file, 'r', self.encoding) as file:
            self.__key = file.readline().strip()
            # end with

        self.__cipher = AESCipher(self.__key)
        # end def

    def decrypt(self, section: str, option: str) -> str:
        if self.__cipher is None:
            self.load_key_file()
            # end if

        raw = self.get(section, option)
        return self.__cipher.decrypt(raw)
        # end if


class AESCipher(object):
    def __init__(self, key, block_size=32):
        self._block_size = block_size
        self.__encoding = sys.getdefaultencoding()
        if len(key) >= block_size:
            self.__key = key[:block_size]
            self.__key = self.__key.encode(self.__encoding)
        else:
            self.__key = Padding.pad(
                key.encode(
                    self.__encoding),
                self._block_size)
            # end if
        # end def

    def encrypt(self, raw):
        iv = Random.get_random_bytes(AES.block_size)
        cipher = AES.new(self.__key, AES.MODE_CBC, iv)
        raw = Padding.pad(raw.encode(self.__encoding), self._block_size)
        return base64.b64encode(iv + cipher.encrypt(raw))
        # end def

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.__key, AES.MODE_CBC, iv)
        data = Padding.unpad(cipher.decrypt(
            enc[AES.block_size:]), self._block_size)
        return data.decode(self.__encoding)
        # end def
    # end class
