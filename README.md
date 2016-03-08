[![Latest Stable Version](https://poser.pugx.org/driftwood/symmetric-encryption/v/stable?format=plastic)](https://packagist.org/packages/driftwood/symmetric-encryption)
[![License](https://poser.pugx.org/driftwood/symmetric-encryption/license?format=plastic)](https://packagist.org/packages/driftwood/symmetric-encryption) 
SymmetricEncryption
===================

PHP wrapper around the OpenSSL library providing preconfigured Authenticated Symmetric Encryption.

- Simple to use
- Uses only well-known cryptographic building blocks
- Authenticated (Encrypt-then-mac)
- Binary safe

Intended use
------------
This class is intended to function as a preconfigured, drop-in option for whenever symetric encryption is needed within your PHP project.

The SymmetricEncryption class is intended to be used 'as-is': the various magic constants defined are *not* configuration options. Instead, they are there to facilitate easy review of choices made. If you change any of the defined constants, or any other part of the code for that matter, the implied security no longer exists; it would be reduced to just another incarnation of home grown crypto.

Review status
-------------
Class SymmetricEncryption has received some informal code reviewing, but not nearly enough to be guaranteed to be secure. Having said that, it is probably more secure than what most people can come up with themselves.

Installation
------------
You can either download the code as a [.zip file](https://github.com/Pixelfck/SymmetricEncryption/archive/master.zip) or use [Composer](https://getcomposer.org/) to download it directly from [packagist](https://packagist.org/packages/driftwood/symmetric-encryption), by adding the following to your composer.json file.

~~~ json
{
	"require": {
		"driftwood/symmetric-encryption": ">=2.0.0"
    }
}
~~~

Usage
-----
Since SymmetricEncryption comes preconfigured, you can encrypt and decrypt data using:
 
~~~ php
// Assuming a PSR-4 compatible autoloader

use Driftwood\SymmetricEncryption;
$password = 'correct horse battery staple';

$crypto = new SymmetricEncryption(20);

$encrypted = $crypto->encrypt('Never roll your own crypto.', $password);
$decrypted = $crypto->decrypt($encrypted, $password);

echo $decrypted; // Never roll your own crypto.
~~~

Maintenance status
------------------
This class is actively maintained, yet there are no frequent updates. This is a good thing: updates would mean that there was something that needed fixing, which is generally a very bad thing in cryptography.

The use of a password instead of a key
--------------------------------------
SymmetricEncryption expects the user to supply a password. However, passwords are, generally speaking, weak authenticators and it would be more secure to require a strong cryptographic key instead. This choice for requiring a password was made to facilitate maximum simplicity (the user supplied password is stretched into a key using PBKDF2). There is (of course) no maximum password length for SymmetricEncryption, nor is there any requirement that it cannot be binary. So you are strongly encouraged to pick a very long, randomly generated set of bytes as your password.
