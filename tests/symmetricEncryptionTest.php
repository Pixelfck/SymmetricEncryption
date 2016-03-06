<?php
namespace TestNamespace;

use Driftwood\SymmetricEncryption;

class SymmetricEncryptionTest extends \PHPUnit_Framework_TestCase {
	
	const PASSWORD = 'correct horse battery staple';
	
	const PLAIN_TEXT = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.';
	
	const CIPHER_TEXT = '0IfYyf22fTOe0x+sBHIEmg8AJY0qoiq1M+fHW55KIvasnMn+s86QOaGPDpv7NUH09Vc0gvvJDSt1NKtK5f3ze2xIKyOU8z9gzISibGPpYyRRxi1N42ixEC42N0bAQPx0RiVgAmj0OYfvLCxUWMjHa9mcGJSMBg7Cu0A=';
	
	/**
	 * Test the Multibyte String functions overloading constructor guard clause
	 */
	public function testMbOverloadStringError() {
		$this->setExpectedException('\\PHPUnit_Framework_Error');
		\Driftwood\setMockFunctionActive('ini_get');
		
		try {
			$crypto = new SymmetricEncryption(12);
		} catch (\PHPUnit_Framework_Error $e) {
			$this->assertEquals($e->getMessage(), 'Incompatible Multibyte String functions overloading detected');
			throw $e;
		}
	}
	
	/**
	 * Test the enforcement of the minimal iterations count constructor guard clause
	 */
	public function testLowIterationsCountWarning() {
		$this->setExpectedException('\\PHPUnit_Framework_Error_Warning');
		
		try {
			$crypto = new SymmetricEncryption(10);
		} catch (\PHPUnit_Framework_Error_Warning $e) {
			$this->assertEquals($e->getMessage(), 'Number of iterations used for key stretching is too low, using default instead');
			throw $e;
		}
	}
	
	/**
	 * Test the openssl_get_cipher_methods output constructor guard clause
	 */
	public function testSupportedCipherMethods() {
		$this->setExpectedException('\\PHPUnit_Framework_Error');
		\Driftwood\setMockFunctionActive('openssl_get_cipher_methods');
		
		try {
			$crypto = new SymmetricEncryption(12);
		} catch (\PHPUnit_Framework_Error $e) {
			$this->assertEquals($e->getMessage(), 'Cipher method AES-128-CFB not available');
			throw $e;
		}
	}
	
	/**
	 * Test the openssl_cipher_iv_length constructor constructor guard clause
	 */
	public function testIvSizeFunctionFailError() {
		$this->setExpectedException('\\PHPUnit_Framework_Error');
		\Driftwood\setMockFunctionActive('openssl_cipher_iv_length');
		
		try {
			$crypto = new SymmetricEncryption(12);
		} catch (\PHPUnit_Framework_Error $e) {
			$this->assertEquals($e->getMessage(), 'Could not determine IV size');
			throw $e;
		}
	}
	
	/**
	 * Test the hash_hmac output length constructor guard clause
	 */
	public function testhashHmacFunctionFailError() {
		$this->setExpectedException('\\PHPUnit_Framework_Error');
		\Driftwood\setMockFunctionActive('hash_hmac');
		
		try {
			$crypto = new SymmetricEncryption(12);
		} catch (\PHPUnit_Framework_Error $e) {
			$this->assertEquals($e->getMessage(), 'Could not determine authentication algorithm output size');
			throw $e;
		}
	}
	
	
	
	/**
	 * 01
	 */
	public function testFetchRandomBytes_readError() {
		$this->setExpectedException('\\Exception');
		\Driftwood\setMockFunctionActive('openssl_random_pseudo_bytes_readError');
		
		try {
			$crypto = new SymmetricEncryption(12);
			$crypto->encrypt(SELF::PLAIN_TEXT, self::PASSWORD);
		} catch (\Exception $e) {
			$this->assertEquals($e->getMessage(), 'Could not read random data');
			throw $e;
		}
	}
	
	/**
	 * 02
	 */
	public function testFetchRandomBytes_qualityFail() {
		$this->setExpectedException('\\Exception');
		\Driftwood\setMockFunctionActive('openssl_random_pseudo_bytes_qualityFail');
		
		try {
			$crypto = new SymmetricEncryption(12);
			$crypto->encrypt(SELF::PLAIN_TEXT, self::PASSWORD);
		} catch (\Exception $e) {
			$this->assertEquals($e->getMessage(), 'Quality of random data is not sufficient for cryptographic use');
			throw $e;
		}
	}
	
	/**
	 * Test the encrypt method against the decrypt method
	 */
	public function testEncryptDecrypt() {
		$crypto = new SymmetricEncryption(12);
		
		$encrypted = $crypto->encrypt(SELF::PLAIN_TEXT, self::PASSWORD);
		
		$this->assertEquals(SELF::PLAIN_TEXT, $crypto->decrypt($encrypted, self::PASSWORD));
	}
	
	/**
	 * Test decryption of know value cipher text
	 */
	public function testDecrypt() {
		$crypto = new SymmetricEncryption(16);
		$this->assertEquals($crypto->decrypt(base64_decode(self::CIPHER_TEXT), self::PASSWORD), 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.');
	}
	
	/**
	 * Test maximum iterations count check
	 */
	public function testTooManyItterationsException() {
		$this->setExpectedException('\\Exception');
		
		$crypto = new SymmetricEncryption(14);
		try {
			$crypto->decrypt(base64_decode(self::CIPHER_TEXT), self::PASSWORD);
		} catch (\Exception $e) {
			$this->assertEquals($e->getMessage(), 'PBKDF2 iterations out of bounds');
			throw $e;
		}
	}
	
	/**
	 * Test signature failure due to wrong password
	 */
	public function testWrongPasswordException() {
		$this->setExpectedException('\\Exception');
		
		$crypto = new SymmetricEncryption(16);		
		try {
			$crypto->decrypt(base64_decode(self::CIPHER_TEXT), 'clueless');
		} catch (\Exception $e) {
			$this->assertEquals($e->getMessage(), 'Signature verification failed!');
			throw $e;
		}
	}
	
	/**
	 * Test signature failure due to tampered iv or cipher text
	 */
	public function testTamperedDataException() {
		$this->setExpectedException('\\Exception');
		
		$crypto = new SymmetricEncryption(16);
		$corrupted = base64_decode('oV7gIO6zYQVRw7vWhjETAQ0AAAAAAAAAAAAAAAAAAAAAABI7ua0JZobYs7reCgmqMKt3DZkKVldsd0f94TRMt+AxHba3XkD/PDxXiUhBJ28z3+iQW7B5');
		
		try {
			$crypto->decrypt($corrupted, 'clueless');
		} catch (\Exception $e) {
			$this->assertEquals($e->getMessage(), 'Signature verification failed!');
			throw $e;
		}
	}
	
	/**
	 * Test decryption failure due internal error in openssl_decrypt (in this case, due to a too short IV value)
	 * Because of the cipher text is authenticated, it would be quite hard to find a corrupted cipher text in a real world use case
	 */
	public function testCorruptedCipherTextException() {
		$this->setExpectedException('\\PHPUnit_Framework_Error_Warning');
		
		$crypto = new SymmetricEncryption(12);
		$corrupted = base64_decode('8i/4Tww0RCH/iZOzcYnAXQwAtAMDwN/p+a8DAGWxeA4cKiWNhTnEtbhzDrxkQXEDolUtV+T7A9L6Bwys1w==');
		try {
			$crypto->decrypt($corrupted, self::PASSWORD); // Warning suppressed because we check the return value
		} catch (\PHPUnit_Framework_Error_Warning $e) {
			$this->assertEquals($e->getMessage(), 'openssl_decrypt(): IV passed is only 11 bytes long, cipher expects an IV of precisely 16 bytes, padding with \0');
			throw $e;
		}
	}
	
	/**
	 * Test generic decryption failure
	 */
	public function testGenericDecryptFail() {
		$this->setExpectedException('\\Exception');
		\Driftwood\setMockFunctionActive('openssl_decrypt');
		
		try {
			$crypto = new SymmetricEncryption(16);
			$crypto->decrypt(base64_decode(self::CIPHER_TEXT), self::PASSWORD);
		} catch (\Exception $e) {
			$this->assertEquals($e->getMessage(), 'Failed decrypting the cipher text');
			throw $e;
		}
	}
}