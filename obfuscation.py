import hashlib
import os


# Generate once and keep private
SECRET_SALT = os.getenv(
    "NETWORK_CATALOG_SALT",
    "CHANGE_THIS_SECRET"
)


def hash_value(value):

    if not value:
        return None

    combined = (
        SECRET_SALT + value
    ).encode()

    return hashlib.sha256(
        combined
    ).hexdigest()