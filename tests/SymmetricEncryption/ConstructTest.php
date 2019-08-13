<?php
namespace Tests\SymmetricEncryption;

use ErrorException;
use Tests\BaseTestCase;
use Driftwood\SymmetricEncryption;
use Netsilik\Testing\Helpers\FunctionOverwrites;


class ConstructTest extends BaseTestCase
{
	/**
	 * Test the Multibyte String functions overloading constructor guard clause
	 */
	public function testMbOverloadStringError()
	{
		self::expectException(ErrorException::class);
		self::expectExceptionMessage('Incompatible Multibyte String functions overloading detected');
		
		FunctionOverwrites::setActive('ini_get', MB_OVERLOAD_STRING);
		
		new SymmetricEncryption(12);
	}
	
	/**
	 * Test the enforcement of the minimal iterations count constructor guard clause
	 */
	public function testLowIterationsCountWarning()
	{
		new SymmetricEncryption(10);
		
		self::assertErrorTriggered(E_USER_WARNING, 'Number of iterations used for key stretching is too low, using default instead');
	}
	
	/**
	 * Test the openssl_get_cipher_methods output constructor guard clause
	 */
	public function testSupportedCipherMethods()
	{
		self::expectException(ErrorException::class);
		self::expectExceptionMessage('Cipher method AES-128-CFB not available');
		
		FunctionOverwrites::setActive('openssl_get_cipher_methods', []);
		
		new SymmetricEncryption(12);
	}
	
	/**
	 * Test the openssl_cipher_iv_length constructor constructor guard clause
	 */
	public function testIvSizeFunctionFailError()
	{
		self::expectException(ErrorException::class);
		self::expectExceptionMessage('Could not determine IV size');
		
		FunctionOverwrites::setActive('openssl_cipher_iv_length', 0);
		
		new SymmetricEncryption(12);
	}
	
	/**
	 * Test the hash_hmac output length constructor guard clause
	 */
	public function testhashHmacFunctionFailError()
	{
		self::expectException(ErrorException::class);
		self::expectExceptionMessage('Could not determine authentication algorithm output size');
		
		FunctionOverwrites::setActive('hash_hmac', false);
		
		new SymmetricEncryption(12);
	}
}
