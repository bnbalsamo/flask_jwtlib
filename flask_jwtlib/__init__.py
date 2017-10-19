"""
flask_jwtlib
"""

__author__ = "Brian Balsamo"
__email__ = "brian@brianbalsamo.com"
__version__ = "0.0.1"

import datetime
from functools import wraps
from flask import request, g
import jwt


# The algo to use to verify JWTs
JWT_ALGO = "RS256"


# =====
# pubkey cache
# =====
# We store the key itself and the last time
# it was retrieved at, so we can keep it fresh
# if we're pulling from the server
PUBKEY_TUPLE = None
# If we explicitly set the pubkey never check it from the server
# We stop checks by setting the time we retrieved it in the distant
# future, so it never ends up too long ago.


def set_permanent_pubkey(pubkey):
    """
    Sets a permanent pubkey

    If this function is called retrieve_pubkey() never
    will be by pubkey()
    """
    global PUBKEY_TUPLE
    PUBKEY_TUPLE = (pubkey, datetime.datetime.max)


def retrieve_pubkey():
    """
    A callback to refresh the pubkey

    Useful if the pubkey is on a remote source and may be changed
    periodically.
    """
    pass


# How long to hold onto a pubkey
# we got from calling retrieve_pubkey()
PUBKEY_CACHE_TIMEOUT = 300


def pubkey():
    """
    Returns the public key used for verifying JWTs

    This function includes the machinery for managing the pubkey cache,
    if one wasn't specified via an env var.

    Note this will **never** refresh the key if one was supplied via
    an env var.
    """
    global PUBKEY_TUPLE
    cache_timeout = datetime.timedelta(seconds=PUBKEY_CACHE_TIMEOUT)
    if not PUBKEY_TUPLE or \
            (datetime.datetime.now() - PUBKEY_TUPLE[1]) > cache_timeout:
        PUBKEY_TUPLE = (retrieve_pubkey(), datetime.datetime.now())
    return PUBKEY_TUPLE[0]

# =====
# Functions for working with tokens
# =====


def check_token(token, pubkey=None):
    """
    Check the token
    Assumes it's in the format the whogoesthere server returns
    """
    global JWT_ALGO
    if pubkey is None:
        pubkey = pubkey()
    try:
        token = jwt.decode(
            token,
            pubkey,
            algorithm=JWT_ALGO
        )
        return True
    except jwt.InvalidTokenError:
        return False


def _get_token_from_header():
    """
    https://tools.ietf.org/html/rfc6750#section-2.1
    """
    try:
        auth_header = request.headers['Authorization']
        if not auth_header.startswith("Bearer: "):
            raise ValueError("Malformed auth header")
        return auth_header[8:]
    except KeyError:
        # Auth isn't in the header
        return None


def _get_token_from_form():
    """
    https://tools.ietf.org/html/rfc6750#section-2.2
    """
    try:
        return request.form['access_token']
    except KeyError:
        return None


def _get_token_from_query():
    """
    https://tools.ietf.org/html/rfc6750#section-2.3
    """
    try:
        return request.args['access_token']
    except KeyError:
        return None


def _DEFAULT_GET_TOKEN():
    """
    Get the token from the response
    Expects the response to supply the token in one of the
    three ways specified in RFC 6750
    """
    # https://tools.ietf.org/html/rfc6750#section-2
    tokens = []

    for x in [_get_token_from_header,
              _get_token_from_form,
              _get_token_from_query]:
        token = x()
        if token:
            tokens.append(token)

    # Be a bit forgiving, don't break if they passed the
    # same token twice, even if they aren't supposed to.
    tokens = set(tokens)

    if len(tokens) > 1:
        raise ValueError("Too many tokens!")
    elif len(tokens) == 1:
        return tokens.pop()
    else:
        return None


def get_token():
    """
    A callback that should return the encoded token

    The default implementation uses **only** the token retrieval methods
    specificed in RFC 6750 - if you want to extend it clobber this function
    with one of your own, optionally calling flask-jwtlib._DEFAULT_GET_TOKEN()
    in your own implementation
    """
    return _DEFAULT_GET_TOKEN()


def get_json_token(verify=True):
    """
    A wrapper for get_token() which decodes the token and returns the JSON

    Verifies the token by default during the operation, but by passing
    the kwarg verify=False you can just get at the json sans verification.
    """
    global JWT_ALGO
    token = get_token()
    json_token = jwt.decode(
        token,
        pubkey(),
        algorithm=JWT_ALGO,
        verify=verify
    )
    return json_token


def is_authenticated():
    """
    Returns whether or not the current request is authenticated
    """
    return g.authenticated


# =====
# Decorators
# =====


def requires_authentication(f):
    """
    A decorator for applying to routes where authentication is required.

    In the event a user is not authenticated the return value of
    flask_jwtlib.requires_authentication.no_auth_callback() will be
    returned.
    """

    def no_auth_callback():
        """
        A callback for when the client doesn't provide a token.
        This callback **should** have a return value.
        """
        raise NotImplementedError(
            'You must specify a callback with a return value ' +
            'at flask_jwtlib.requires_authentication.no_auth_callback()'
        )

    @wraps(f)
    def decorated(*args, **kwargs):
        # Defaults
        g.authenticated = False
        g.raw_token = None
        g.json_token = None

        try:
            token = get_token()
        except ValueError:
            # Something is wrong with the token formatting
            return no_auth_callback()
        if not token:
            # Token isn't in the request or the session
            return no_auth_callback()
        if not check_token(token):
            # The token isn't valid
            return no_auth_callback()
        g.authenticated = True
        g.raw_token = get_token()
        g.json_token = get_json_token()
        return f(*args, **kwargs)
    return decorated


def optional_authentication(f):
    """
    A decorator for applying to routes where authentication is optional.

    In the event a user is not authenticated
    flask_jwtlib.optional_authentication.no_auth_callback() will be
    called, but the decorated endpoint will still be returned.
    """

    def no_auth_callback():
        """
        A callback for when the client doesn't provide a token.
        This callback **should not** have a return value.

        Dumping any (now invalid) tokens out of caches should
        probably be done here.
        """
        pass

    @wraps(f)
    def decorated(*args, **kwargs):
        # Defaults
        g.authenticated = False
        g.raw_token = None
        g.json_token = None

        try:
            token = get_token()
        except ValueError:
            # Something is wrong with the token formatting
            # formatting
            no_auth_callback()
            return f(*args, **kwargs)
        if not token:
            # Token isn't in the request or the session
            no_auth_callback()
            return f(*args, **kwargs)
        json_token = check_token(token)
        if not json_token:
            # The token isn't valid
            no_auth_callback()
            return f(*args, **kwargs)
        g.authenticated = True
        g.raw_token = get_token()
        g.json_token = get_json_token()
        return f(*args, **kwargs)
    return decorated
