CHANGE LOG:
-----------

Version 1.03
- Added unit tests
- Updated project structure for compatibility with [PSR-4](http://www.php-fig.org/psr/psr-4/) and [Composer](https://getcomposer.org/)
- Improved hash_hmac expected output length validity check

Version 1.02
- Updated the doc block example inside symmetricEncryption.class.php
- Updated the example code inside example.php
- Updated the readme

Version 1.01
- Added changelog file,
- Added constant time signature verification as to prevent possible timing attacks,
- Made sure the library now uses AES-128 instead of AES-256,
- Having Multibyte String string function overloading active now results in a E_USER_ERROR,
- Removed build-in support for compression.

Version 1.0
- Initial release.