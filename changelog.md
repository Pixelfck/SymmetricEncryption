CHANGE LOG:
-----------

Version 2.0.1
- Fixed capitalisation issue that caused an issue with PSR4 auto loading,
- Fixed coding style issue (whitespace usage),
- Added .gitignore and .gitattributes files.

Version 2.0.0
- Replaced `mcrypt_` family of functions with the `openssl_` family of functions,
- Added some more unit tests.

Version 1.1.2
- Added unit tests,
- Updated project structure for compatibility with [PSR-4](http://www.php-fig.org/psr/psr-4/) and [Composer](https://getcomposer.org/),
- Improved hash_hmac expected output length validity check.

Version 1.1.1
- Updated the doc block example inside symmetricEncryption.class.php,
- Updated the example code inside example.php,
- Updated the readme.

Version 1.1.0
- Added changelog file,
- Added constant time signature verification as to prevent possible timing attacks,
- Made sure the library now uses AES-128 instead of AES-256,
- Having Multibyte String string function overloading active now results in a E_USER_ERROR,
- Removed build-in support for compression.

Version 1.0.0
- Initial release.
