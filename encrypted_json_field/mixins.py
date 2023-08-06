import base64

from typing import Union

from Crypto import Random
from Crypto.Cipher import AES
from django.conf import settings


class EncryptionMixin:
    """Encryption protocol mixin."""

    _BS = 16
    _KEY = settings.ENCRYPTED_JSON_SECRET_KEY if hasattr(settings, "ENCRYPTED_JSON_FIELD_SECRET") else settings.SECRET_KEY
    _KEY_BYTES = bytes(_KEY[:_BS], "utf-8")

    def _pad(self, value: str) -> bytes:
        """Pad string to conceal start and end of value."""

        return bytes(value + (self._BS - len(value) % self._BS) * chr(self._BS - len(value) % self._BS), "utf-8")

    def _unpad(self, value: bytes) -> bytes:
        """Unpad string and return orginal value."""

        return value[0:-ord(value[-1:])]

    def encrypt(self, raw_value: str) -> bytes:
        """Encrypt and encode string."""

        data = self._pad(raw_value)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self._KEY_BYTES, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(data))

    def decrypt(self, encrypted_value: Union[str, bytes]) -> str:
        """Decrypt and decode database value."""

        data = base64.b64decode(encrypted_value)
        iv = data[:self._BS]
        cipher = AES.new(self._KEY_BYTES, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(data[self._BS:])).decode("utf8")
