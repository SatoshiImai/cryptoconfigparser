# coding:utf-8
# ---------------------------------------------------------------------------
# __author__ = 'Satoshi Imai'
# __credits__ = ['Satoshi Imai']
# __version__ = '0.9.0'
# ---------------------------------------------------------------------------

import logging
from typing import Tuple

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.structures import MessageHeader

from . import AESCryptoConfigParser


class KMSCryptoConfigParser(AESCryptoConfigParser):

    SETTING_SECTION_KEY = 'settings'
    KMS_KEY_ID_OPTION_KEY = 'key_id'

    def __init__(self,
                 config_path: str = None,
                 encoding: str = None):
        super(KMSCryptoConfigParser, self).__init__(config_path, encoding)

        self.__key_id = None

        if config_path:
            if self.has_option(self.SETTING_SECTION_KEY,
                               self.KMS_KEY_ID_OPTION_KEY):
                # load key_id
                self.__key_id = self.get(
                    self.SETTING_SECTION_KEY, self.KMS_KEY_ID_OPTION_KEY)
                # end if
            # end if
        # end def

    def get_key_id(self) -> str:
        return self.__key_id
        # end def

    def set_key_id(self, value: str):
        self.__key_id = value
        # end def

    key_id = property(get_key_id, set_key_id)

    def encrypt(self, text: str) -> Tuple[str, MessageHeader]:
        client = aws_encryption_sdk.EncryptionSDKClient(
            commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)

        kms_key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(key_ids=[
            self.__key_id
        ])

        my_ciphertext, encryptor_header = client.encrypt(
            source=text,
            key_provider=kms_key_provider
        )

        return my_ciphertext.hex(), encryptor_header
        # end def

    def decrypt(self, section: str, option: str) -> str:

        decrypted = None
        if self.__key_id is None:
            decrypted = super(
                KMSCryptoConfigParser,
                self).decrypt(
                section,
                option)
        else:
            raw = self.get(section, option)
            my_ciphertext = bytes.fromhex(raw)
            client = aws_encryption_sdk.EncryptionSDKClient(
                commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)

            kms_key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(key_ids=[
                self.__key_id
            ])
            decrypted, decryptor_header = client.decrypt(
                source=my_ciphertext,
                key_provider=kms_key_provider
            )
            logger = logging.getLogger(__name__)
            logger.debug(decryptor_header)
            # end if
        return decrypted
        # end def
    # end class
