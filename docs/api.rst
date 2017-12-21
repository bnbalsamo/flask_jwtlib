API
===

Module Level Attributes
-----------------------

.. autodata:: flask_jwtlib.JWT_ALGO

.. autodata:: flask_jwtlib.VERIFICATION_KEY_CACHE_TIMEOUT

Functions
---------

.. autofunction:: flask_jwtlib.set_permanent_verification_key

.. autofunction:: flask_jwtlib.verification_key

.. autofunction:: flask_jwtlib.get_json_token

.. autofunction:: flask_jwtlib.is_authenticated

Callbacks
---------

Functionality may be changed or introduced by registering callbacks to these
functions.

.. autofunction:: flask_jwtlib.retrieve_verification_key

.. autofunction:: flask_jwtlib.check_token

.. autofunction:: flask_jwtlib.get_token

.. autofunction:: flask_jwtlib.requires_authentication_failure_callback

.. autofunction:: flask_jwtlib.optional_authentication_failure_callback

Decorators
----------

.. autofunction:: flask_jwtlib.requires_authentication

.. autofunction:: flask_jwtlib.optional_authentication

Default Callback Implementations
--------------------------------

These functions are provided as default implementations for callbacks, and should not
be overriden in order to change functionality (unless you really know what you're doing).

Instead, in order to alter callback behavior override the callback function itself, optionally
calling the default implementations as provided here if you want to extend, rather than 
override, the functionality.

.. autofunction:: flask_jwtlib._DEFAULT_CHECK_TOKEN

.. autofunction:: flask_jwtlib._DEFAULT_GET_TOKEN

.. autofunction:: flask_jwtlib._DEFAULT_REQUIRES_AUTHENTICATION_FAILURE_CALLBACK

.. autofunction:: flask_jwtlib._DEFAULT_OPTIONAL_AUTHENTICATION_FAILURE_CALLBACK
