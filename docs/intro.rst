Introduction
============

:mod:`flask_jwtlib` is a library for working with `JSON Web Tokens (JWTs) <https://jwt.io/>`_.

For more information on JWTs see `this introduction <https://jwt.io/introduction/>`_ and :rfc:`7519`

This library is meant to be minimal and unopinionated - it concerns itself *strictly* with reading and effectively utilizing JWTs, rather than with their creation, dissemination, or claims outside of those explicitly defined in the JWT specification, leaving those concerns to implementing projects. 

This means :mod:`flask_jwtlib` can be of use to both identity providing services as well as services which consume validated identities from any compatible provider.

While this solution isn't as "batteries included" as others, I believe it makes up for it by staying out of the way regarding implementation details outside of the JWT specification itself.
