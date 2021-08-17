import base64
import jwt
import requests

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from typing import Dict


class InvalidOauthToken(Exception):
    def __init__(self, message):
        super().__init__(f'Invalid Oauth2 token: {message}')


def decode_jwk_val(val: str) -> int:
    """Function decodes jwv values into integers

    :param str val: the values to decode

    :return: The decoded value
    :rtype: int
    """
    if isinstance(val, str):
        val = val.encode('utf-8')
    decoded = base64.urlsafe_b64decode(val + b'==')
    return int.from_bytes(decoded, 'big')


def get_rsa_pem(jwk: Dict) -> bytes:
    """Function extracts the rsa key from the jwk

    :param str jwk: The Java Web Key

    :return: The public key
    :rtype: bytes
    """
    pem = RSAPublicNumbers(
        e=decode_jwk_val(jwk['e']),
        n=decode_jwk_val(jwk['n'])
    )
    pem = pem.public_key(backend=default_backend())
    pem = pem.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem


def decode_token(token: str, aud: str) -> Dict:
    """Function decodes a jwt token from azure ad

    :param str token: The token
    :param str aud: The token audience

    :return: The decoded token
    :rtype: Dict

    :raises InvalidOauthToken: When the token is invalid
    :raier jwt.exceptions.ExpiredSignatureError: Expired token
    """
    # Get the jwks from microsoft
    jwks = requests.get('https://login.microsoftonline.com/common/discovery/keys').json()

    # Get the header from the token
    headers = jwt.get_unverified_header(token)
    if 'kid' not in headers:
        raise InvalidOauthToken('Missing kid')

    # Get the corresponding jwk
    filtered_jwks = [jwk for jwk in jwks['keys'] if jwk['kid'] == headers['kid']]
    if not filtered_jwks:
        raise InvalidOauthToken('kid not valid')
    jwk = filtered_jwks[0]

    # Get the key
    pem = get_rsa_pem(jwk)

    # Decode the token
    decoded = jwt.decode(
        jwt=token,
        key=pem,
        algorithms=headers['alg'],
        audience=aud,
    )

    return decoded
