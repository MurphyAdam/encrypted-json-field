# Encrypted JSON Field

Encrypted JSON field supports automatic encryption/ decryption of JSON fields with padding to conceal start and end of value.

## Setup

Nothing really to setup, just import the field and get to work.
You could, however, setup an optional variable in your django settings named `ENCRYPTED_JSON_FIELD_SECRET` (It should be 16 chars minimum) which will be used to encrypt/ decrypt
the data of your fields. The default behaviour uses the first 16 characters of `SECRET_KEY` (Block size).

### Example:

```py
from encrypted_json_field import EncryptedJSONField
from django.db import models


class Company(models.Model):
    name = models.CharField(max_length=32)
    config = EncryptedJSONField(blank=True)

```

### Support
This supports Python >= 3.8 and Django >= 4.2.
If you need to support other versions, please create an issue.