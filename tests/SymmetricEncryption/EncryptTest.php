<?php
namespace Tests\SymmetricEncryption;

use Exception;
use Tests\BaseTestCase;
use Driftwood\SymmetricEncryption;
use Netsilik\Testing\Helpers\FunctionOverwrites;


class EncryptTest extends BaseTestCase
{
	
	const PASSWORD   = 'correct horse battery staple';
	
	const PLAIN_TEXT = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.';
	
	/**
	 * 01
	 */
	public function testFetchRandomBytes_readError()
	{
		self::expectException(Exception::class);
		self::expectExceptionMessage('Could not read random data');
		
		FunctionOverwrites::setActive('openssl_random_pseudo_bytes', 'readError');
		
		$crypto = new SymmetricEncryption(12);
		$crypto->encrypt(self::PLAIN_TEXT, self::PASSWORD);
	}
	
	/**
	 * 02
	 */
	public function testFetchRandomBytes_qualityFail()
	{
		self::expectException(Exception::class);
		self::expectExceptionMessage('Quality of random data is not sufficient for cryptographic use');
		
		FunctionOverwrites::setActive('openssl_random_pseudo_bytes', 'qualityFail');
		
		$crypto = new SymmetricEncryption(12);
		$crypto->encrypt(self::PLAIN_TEXT, self::PASSWORD);
	}
	
	/**
	 * Test the encrypt method against the decrypt method
	 */
	public function testEncryptDecrypt()
	{
		$crypto = new SymmetricEncryption(12);
		
		$encrypted = $crypto->encrypt(self::PLAIN_TEXT, self::PASSWORD);
		
		$this->assertEquals(self::PLAIN_TEXT, $crypto->decrypt($encrypted, self::PASSWORD));
	}
}
