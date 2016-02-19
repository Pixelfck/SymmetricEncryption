<?php
namespace TestNamespace;

use Driftwood\SymmetricEncryption;

class SymmetricEncryptionTest extends \PHPUnit_Framework_TestCase {
	
	const PASSWORD = 'correct horse battery staple';
	
	private $_encrypted = null;
	
	public function setUp() {
		$this->_encrypted = base64_decode('E7yiRHL84CCzJ+gIu6YVNRQAjZfGnFgG7jDq0LiJoeF3mvhVOikMemU+IdnNNKFfxnpSbJWfqIPwLVHx9IAy7Wu+la1Rsv3MJJpXWIRoJWD9OMa7meEqlKY8J4+RUvKDtIu4g7YYhl04T4i7fLqmCHFMJOkyJ50Ti7g=');
	}
	
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
	 * Test the mcrypt_get_iv_size constructor constructor guard clause
	 */
	public function testIvSizeFunctionFailError() {
		$this->setExpectedException('\\PHPUnit_Framework_Error');
		\Driftwood\setMockFunctionActive('mcrypt_get_iv_size');
		
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
	 * Test the encrypt method against the decrypt method
	 */
	public function testEncryptDecrypt() {
		$plainText = 'Never roll your own crypto test.';
		
		$crypto = new SymmetricEncryption(12);
		
		$encrypted = $crypto->encrypt($plainText, self::PASSWORD);
		
		$this->assertEquals($plainText, $crypto->decrypt($encrypted, self::PASSWORD));
	}
	
	/**
	 * Test decryption of know value cipher text
	 */
	public function testDecrypt() {
		$crypto = new SymmetricEncryption(20);
		$this->assertEquals($crypto->decrypt($this->_encrypted, self::PASSWORD), 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.');
	}
	
	/**
	 * Test maximum iterations count check
	 */
	public function testTooManyItterationsException() {
		$this->setExpectedException('\\Exception');
		
		$crypto = new SymmetricEncryption(16);
		try {
			$crypto->decrypt($this->_encrypted, self::PASSWORD);
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
		
		$crypto = new SymmetricEncryption(20);		
		try {
			$crypto->decrypt($this->_encrypted, 'clueless');
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
		
		$crypto = new SymmetricEncryption(20);
		$corrupted = base64_decode('oV7gIO6zYQVRw7vWhjETAQ0AAAAAAAAAAAAAAAAAAAAAABI7ua0JZobYs7reCgmqMKt3DZkKVldsd0f94TRMt+AxHba3XkD/PDxXiUhBJ28z3+iQW7B5');
		
		try {
			$crypto->decrypt($corrupted, 'clueless');
		} catch (\Exception $e) {
			$this->assertEquals($e->getMessage(), 'Signature verification failed!');
			throw $e;
		}
	}
	
	/**
	 * Test decryption failure due internal error in mcrypt_decrypt (in this case, due to a too short IV value)
	 * Because of the cipher text is authenticated, it would be quite hard to find a corrupted cipher text in a real world use case
	 */
	public function testCorruptedCipherTextException() {
		$this->setExpectedException('\\Exception');
		
		$crypto = new SymmetricEncryption(12);
		$corrupted = base64_decode('bI+svL8MnzGuDJZu5k2ppgwAAAAAAAAAAAAAAAAAAAAAgu62ymOxM77feP7z/CJybN22g8BuaQZ2dzmkTTNDSSY=');
		try {
			@$crypto->decrypt($corrupted, self::PASSWORD); // Warning suppressed because we check the return value
		} catch (\Exception $e) {
			$this->assertEquals($e->getMessage(), 'Failed decrypting the cipher text');
			throw $e;
		}
	}
}