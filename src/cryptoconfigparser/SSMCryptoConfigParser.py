# coding:utf-8
# ---------------------------------------------------------------------------
# __author__ = 'Satoshi Imai'
# __credits__ = ['Satoshi Imai']
# __version__ = '0.9.0'
# ---------------------------------------------------------------------------

import json

import boto3

from . import AESCipher, AESCryptoConfigParser


class SSMCryptoConfigParser(AESCryptoConfigParser):

    SETTING_SECTION_KEY = 'settings'
    SECRET_NAME_OPTION_KEY = 'secret_name'

    def __init__(self,
                 config_path: str = None,
                 encoding: str = None,
                 profile: str = None,
                 region: str = None):
        super(SSMCryptoConfigParser, self).__init__(config_path, encoding)

        self.__cipher = None
        self.__profile = None
        self.__secret_name = None
        self.__region = 'ap-northeast-1'
        if profile:
            self.__profile = profile
            # end if
        if region:
            self.__region = region
            # end if

        if config_path:
            if self.has_option(self.SETTING_SECTION_KEY,
                               self.SECRET_NAME_OPTION_KEY):
                # load key
                self.__secret_name = self.get(
                    self.SETTING_SECTION_KEY, self.SECRET_NAME_OPTION_KEY)
                self.load_secret()
                # end if
            # end if
        # end def

    def get_secret_name(self) -> str:
        return self.__secret_name
        # end def

    def set_secret_name(self, value: str):
        self.__secret_name = value
        self.__cipher = None
        # end def

    secret_name = property(get_secret_name, set_secret_name)

    def get_profile(self) -> str:
        return self.__profile
        # end def

    def set_profile(self, value: str):
        self.__profile = value
        # end def

    profile = property(get_profile, set_profile)

    def get_region(self) -> str:
        return self.__region
        # end def

    def set_region(self, value: str):
        self.__region = value
        # end def

    region = property(get_region, set_region)

    def load_secret(self,
                    name: str = None,
                    profile: str = None,
                    region: str = None):
        if name:
            self.secret_name = name
            # end if
        if profile:
            self.profile = profile
            # end if
        if region:
            self.region = region
            # end if

        if self.secret_name is None:
            return
            # end if

        session = boto3.session.Session(profile_name=self.profile)
        client = session.client(
            service_name='secretsmanager',
            region_name=self.region,
        )

        get_secret_value_response = client.get_secret_value(
            SecretId=self.secret_name)
        if 'SecretString' in get_secret_value_response:
            secret = json.loads(get_secret_value_response['SecretString'])

            self.__key = secret['key']
            # end if

        # init cipher
        self.__cipher = AESCipher(self.__key)
        # end def

    def decrypt(self, section: str, option: str) -> str:
        if self.__cipher is None:
            self.load_secret()
            # end if

        decrypted = None
        if self.__cipher is None:
            decrypted = super(
                SSMCryptoConfigParser,
                self).decrypt(
                section,
                option)
        else:
            raw = self.get(section, option)
            decrypted = self.__cipher.decrypt(raw)
            # end if
        return decrypted
        # end def
    # end class
