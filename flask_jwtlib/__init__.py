"""
flask_jwtlib
"""

__author__ = "Brian Balsamo"
__email__ = "brian@brianbalsamo.com"
__version__ = "0.0.2"

import datetime
from functools import wraps
from flask import request, g, abort
import jwt


#: The algorithm to use to verify JWTs.
#:
#: This should be a string recognizable
#: to :func:`jwt.decode`'s 'algorithm' kwarg.
JWT_ALGO = "RS256"


# Defaults
def _DEFAULT_CHECK_TOKEN(token):
    """
    The default implementation of the token checking function,
    exposed as :func:`check_token`.

    :param str token: The token as an encoded string.
    :returns: Whether or not the token is valid
    :rtype: bool
    """

    global JWT_ALGO
    try:
        token = jwt.decode(
            token,
            verification_key(),
            algorithm=JWT_ALGO
        )
        return True
    except jwt.InvalidTokenError:
        return False


def _DEFAULT_GET_TOKEN():
    """
    The default implementation of retrieving a bearer token
    from a request, exposed as :func:`get_token`.

    Expects the request to supply the token in one of the
    three ways specified in :rfc:`6750`:
        * via the header
        * via a form argument
        * via the query string

    :returns: The token, or None
    :rtype: str or NoneType
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


def _DEFAULT_REQUIRES_AUTHENTICATION_FAILURE_CALLBACK():
    """
    The default callback for failing to provide authentication
    when it is required: Throw a 401. Exposed as
    :func:`requires_authentication_failure_callback`.

    :returns: A 401 response
    """
    return abort(401)


def _DEFAULT_OPTIONAL_AUTHENTICATION_FAILURE_CALLBACK():
    """
    The default callback for failing to provide authentication
    when it is optional: Do nothing. Exposed as
    :func:`optional_authentication_failure_callback`.
    """
    pass


# =====
# verification key cache
# =====

#: We store the key itself and the last time
#: it was retrieved at, so we can keep it fresh
#: if we're pulling from the server
_VERIFICATION_KEY_TUPLE = None

#: How long to hold onto a verification key
#: we get from calling :func:`retrieve_verification_key` in seconds.
#:
#: **Note**: This value will be ignored if :func:`set_permanent_verification_key`
#: has been called.
VERIFICATION_KEY_CACHE_TIMEOUT = 300


# If we explicitly set the verification key never check it from the server
# We stop checks by setting the time we retrieved it in the distant
# future, so it never ends up too long ago.
def set_permanent_verification_key(verification_key):
    """
    Sets a permanent verification key

    **Note**: If this function is called :func:`retrieve_verification_key` never
    will be by :func:`verification_key`

    :param str verification_key: The key to *always* use for verification
    :returns: None
    :rtype: NoneType
    """
    global _VERIFICATION_KEY_TUPLE
    _VERIFICATION_KEY_TUPLE = (verification_key, datetime.datetime.max)


def retrieve_verification_key():
    """
    A callback to refresh the verification key

    Useful if the verification key is on a remote source and may be changed
    periodically.

    If implemented, this function should return the verification key as a str or,
    in the event of failure, raise an exception.

    :raises NotImplemented: if no callback is registered
    """
    raise NotImplemented()


def verification_key():
    """
    Returns the verification key used for verifying JWTs.

    This function includes the machinery for managing the verification key cache, and is
    how all other functions/decorators which require it retrieve the verification key
    internally.

    :returns: The verification key
    :rtype: str
    """
    global _VERIFICATION_KEY_TUPLE
    cache_timeout = datetime.timedelta(seconds=VERIFICATION_KEY_CACHE_TIMEOUT)
    if not _VERIFICATION_KEY_TUPLE or \
            (datetime.datetime.now() - _VERIFICATION_KEY_TUPLE[1]) > cache_timeout:
        _VERIFICATION_KEY_TUPLE = (retrieve_verification_key(), datetime.datetime.now())
    return _VERIFICATION_KEY_TUPLE[0]


# =====
# Functions for working with tokens
# =====
def check_token(token):
    """
    Check the token. This function will be called from within
    the decorators to determine if a token is valid or not.

    You should override this function if token validity within
    your service is determined by anything other than *strictly*
    the validity of the token signature, eg: token key values.

    For the default implementation see :func:`_DEFAULT_CHECK_TOKEN`

    :returns: Whether or not the token is valid
    :rtype: bool
    """
    return _DEFAULT_CHECK_TOKEN(token)


def _get_token_from_header():
    """
    Tries to get a bearer token from the HTTP header

    https://tools.ietf.org/html/rfc6750#section-2.1

    :rtype: str or NoneType
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
    Tries to get a bearer token from a form variable

    https://tools.ietf.org/html/rfc6750#section-2.2

    :rtype: str or NoneType
    """
    try:
        return request.form['access_token']
    except KeyError:
        return None


def _get_token_from_query():
    """
    Tries to get a bearer token from the query string

    https://tools.ietf.org/html/rfc6750#section-2.3

    :rtype: str or NoneType
    """
    try:
        return request.args['access_token']
    except KeyError:
        return None


def get_token():
    """
    A callback that should return the encoded token

    The default implementation uses **only** the token retrieval methods
    specificed in :rfc:`6750`. If you want to extend it override this function
    with one of your own, optionally calling :func:`flask_jwtlib._DEFAULT_GET_TOKEN()`
    in your own implementation

    :returns: The token, or None if no token could be retrieved
    :rtype: str or NoneType
    """
    return _DEFAULT_GET_TOKEN()


def get_json_token(verify=True):
    """
    A wrapper for :func:`get_token` which decodes the token and returns the JSON

    :param bool verify: Whether or not to verify the token, as well as decoding it
    :returns: The decoded token
    :rtype: dict
    """
    global JWT_ALGO
    token = get_token()
    json_token = jwt.decode(
        token,
        verification_key(),
        algorithm=JWT_ALGO,
        verify=verify
    )
    return json_token


def is_authenticated():
    """
    :returns: Whether or not the current request is authenticated
    :rtype: bool
    """
    return g.authenticated


# =====
# Decorators / Callbacks used in decorators
# =====
def requires_authentication_failure_callback():
    """
    A callback for when the client doesn't provide a valid token.

    This callback **must** have a return value.

    For the default implementation see :func:`_DEFAULT_REQUIRES_AUTHENTICATION_FAILURE_CALLBACK`

    :returns: A response
    """
    return _DEFAULT_REQUIRES_AUTHENTICATION_FAILURE_CALLBACK()


def optional_authentication_failure_callback():
    """
    A callback for when the client doesn't provide a token.
    This callback **should not** have a return value.

    Dumping any (now invalid) tokens out of caches should
    probably be done here.

    For the default implementation see :func:`_DEFAULT_OPTIONAL_AUTHENTICATION_FAILURE_CALLBACK`
    """
    _DEFAULT_OPTIONAL_AUTHENTICATION_FAILURE_CALLBACK()


def requires_authentication(f):
    """
    A decorator for applying to routes where authentication is required.

    In the event a user is not authenticated the return value of
    :func:`requires_authentication_failure_callback` will be
    returned **instead** of the return value of the route.

    In any decorated endpoint, sets the following attributes on :attr:`flask.g` on success:
        * authenticated (bool): Whether or not the user is authenticated
        * raw_token (str): The encoded token
        * json_token (dict): The decoded token as a dict
    """
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
            return requires_authentication_failure_callback()
        if not token:
            # Token isn't in the request or the session
            return requires_authentication_failure_callback()
        if not check_token(token):
            # The token isn't valid
            return requires_authentication_failure_callback()
        g.authenticated = True
        g.raw_token = get_token()
        g.json_token = get_json_token()
        return f(*args, **kwargs)
    return decorated


def optional_authentication(f):
    """
    A decorator for applying to routes where authentication is optional.

    In the event a user is not authenticated
    :func:`optional_authentication_failure_callback` will be
    called, but the decorated endpoint will still be returned.

    In any decorated endpoint, sets the following attributes on flask.g:
        * authenticated (bool): Whether or not the user is authenticated
        * raw_token (str or None): The encoded token, or None if no token was provided
        * json_token (dict or None): The decoded token as a dict, or None if no token was provided.
    """
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
            optional_authentication_failure_callback()
            return f(*args, **kwargs)
        if not token:
            # Token isn't in the request or the session
            optional_authentication_failure_callback()
            return f(*args, **kwargs)
        json_token = check_token(token)
        if not json_token:
            # The token isn't valid
            optional_authentication_failure_callback()
            return f(*args, **kwargs)
        g.authenticated = True
        g.raw_token = get_token()
        g.json_token = get_json_token()
        return f(*args, **kwargs)
    return decorated
