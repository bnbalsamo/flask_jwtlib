Usage
=====

Basic Setup
-----------

:mod:`flask_jwtlib` contains two module level variables which may be configured:

* :data:`flask_jwtlib.JWT_ALGO`: This variable is a string denoting the JWT algorithm 
  which will be used as the argument to :func:`jwt.decode`'s algorithm kwarg internally. 
  It defaults to "RS256"
* :data:`flask_jwtlib.VERIFICATION_KEY_CACHE_TIMEOUT`: This variable is an int which defines 
  the amount of time a key retrieved by :func:`flask_jwtlib.retrieve_verification_key` 
  will be considered valid, in seconds. It defaults to 300.
    * This option can be safely ignored if instead of defining a 
      :func:`flask_jwtlib.retrieve_verification_key` callback you instead call 
      :func:`flask_jwtlib.set_permanent_verification_key`


Minimal Usage
-------------

There are two ways to minimally utilize flask_jwtlib:

* Implementing a :func:`flask_jwtlib.retrieve_verification_key` callback
* Providing the library with a key via calling :func:`flask_jwtlib.set_permanent_verification_key`

Once you have provided access to the verification key via either of the two above methods, the
library provides two basic decorators for routes:

* :func:`flask_jwtlib.requires_authentication`, which will cause unauthenticated clients to
  be 401'd, or pass authenticated clients through to the decorated route
* :func:`flask_jwtlib.optional_authentication`, which will pass all clients through to the
  decorated route

Both of these decorators will populate the following on :data:`flask.g`

* :attr:`flask.g.authenticated`: A boolean, whether or not the client is authenticated
* :attr:`flask.g.raw_token`: The encoded JWT token, as a str
* :attr:`flask.g.json_token`: The decoded JWT token as a dict, if possible

Minimal Example
^^^^^^^^^^^^^^^

A minimal example flask application follows::

    from json import dumps
    from flask import Flask, g
    from flask_jwtlib import requires_authentication, optional_authentication, \
        set_permanent_verification_key

    app = Flask(__name__)

    set_permanent_verification_key("Your super secret key goes here")

    @optional_authentication
    @app.route("/")
    def hello():
        if g.authenticated:
            return "Your JWT claims look like...\n{}!".format(
                dumps(g.json_token, indent=2)
            )
        else:
            return "You don't have a (valid) token!"

    @requires_authentication
    @app.route("/secure")
    def secure():
        return "This JWT is valid: {}".format(g.raw_token)


Advanced Usage
--------------

:mod:`flask_jwtlib` exposes as much functionality as possible via callbacks. Callbacks 
which may be overridden in order to change the behaviors of the decorators are documented
in the API Reference under "Callbacks".

In order to facilitate extending, rather than just overriding, the default callbacks the
default implementations are exposed as a separate set of functions, documented in the API
Reference under "Default Callback Implementations"

Advanced Example
^^^^^^^^^^^^^^^^

Advanced examples can be seen in the source of `ipseity <https://github.com/bnbalsamo/ipseity>`_ and its test client site.
