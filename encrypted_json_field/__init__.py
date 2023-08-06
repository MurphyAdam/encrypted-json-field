import json
from encrypted_json_field.mixins import EncryptionMixin

from django.core.exceptions import ValidationError
from django.db.models import JSONField


class EncryptedJSONField(EncryptionMixin, JSONField):
    """
    Encrypted JSON field supports encryption/ decryption of JSON fields.

    We encrypt the whole JSON object after it has been dumped as string,
    then we save this string as the value of a `_data` key.

    E.g.
    object = {"id": 1, "name": "Bob", "others": ["A", "B"]}
    would be encrypted in the database as: {"_data": "gAAAAABh-uRqCz0ILSIarvW_u8oUEFMcMWBpt2q0jvWzRQ_..."}
    """

    description = "Encrypted JSON field"

    def to_python(self, value):
        """
        Decrypt data and serialize it to native Python types.

        We need to count for value param data type and the `_data` key as
        this method is called by different methods.
        """

        if value is None:
            return value

        if isinstance(value, (bytes, str)):
            try:
                value = json.loads(value, cls=self.decoder)
                # data is encrypted
                if isinstance(value, str):
                    return self.to_python(value)
                if _data := value.get("_data", None):
                    value = _data
                # data is not encrypted (e.g. migrations haven't taken place yet.)
                else:
                    return value
            except json.JSONDecodeError:
                raise ValidationError(
                    "Failed to decode JSON value.",
                    code="invalid_json",
                    params={"value": value}
                )
        elif _data := value.get("_data", None):
            value = _data
        else:
            return value
        try:
            if isinstance(value, dict):
                value = json.dumps(value, cls=self.encoder)
            return json.loads(self.decrypt(value))
        except Exception as exc:
            raise ValidationError(
                "Failed to decrypt. {exception}").format(exception=exc,
                code="decryption_failure",
                params={"value": value}
            )

    def from_db_value(self, value, *args, **kwargs):
        """Decrypt data and serialize it to Python types."""

        return self.to_python(value)

    def get_prep_value(self, value) -> dict | None:
        """Encrypt data and serialize it to string type."""

        if value is None:
            return value
        encrypted_value = self.encrypt(json.dumps(value, cls=self.encoder)).decode("utf-8")
        return {"_data": encrypted_value}
