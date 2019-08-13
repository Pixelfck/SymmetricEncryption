<?php
namespace Tests\SymmetricEncryption;

use Exception;
use Tests\BaseTestCase;
use Driftwood\SymmetricEncryption;
use Netsilik\Testing\Helpers\FunctionOverwrites;


class DecryptTest extends BaseTestCase
{
	
	const PASSWORD    = 'correct horse battery staple';
	
	const CIPHER_TEXT = '0IfYyf22fTOe0x+sBHIEmg8AJY0qoiq1M+fHW55KIvasnMn+s86QOaGPDpv7NUH09Vc0gvvJDSt1NKtK5f3ze2xIKyOU8z9gzISibGPpYyRRxi1N42ixEC42N0bAQPx0RiVgAmj0OYfvLCxUWMjHa9mcGJSMBg7Cu0A=';
	
	/**
	 * Test decryption of know value cipher text
	 */
	public function testDecrypt()
	{
		$crypto = new SymmetricEncryption(16);
		$this->assertEquals($crypto->decrypt(base64_decode(self::CIPHER_TEXT), self::PASSWORD), 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.');
	}
	
	/**
	 * Test maximum iterations count check
	 */
	public function testTooManyItterationsException()
	{
		self::expectException(Exception::class);
		self::expectExceptionMessage('PBKDF2 iterations out of bounds');
		
		$crypto = new SymmetricEncryption(14);
		$crypto->decrypt(base64_decode(self::CIPHER_TEXT), self::PASSWORD);
	}
	
	/**
	 * Test signature failure due to wrong password
	 */
	public function testWrongPasswordException()
	{
		self::expectException(Exception::class);
		self::expectExceptionMessage('Signature verification failed!');
		
		$crypto = new SymmetricEncryption(16);
		$crypto->decrypt(base64_decode(self::CIPHER_TEXT), 'clueless');
	}
	
	/**
	 * Test signature failure due to tampered iv or cipher text
	 */
	public function testTamperedDataException()
	{
		self::expectException(Exception::class);
		self::expectExceptionMessage('Signature verification failed!');
		
		$crypto    = new SymmetricEncryption(16);
		$corrupted = base64_decode('oV7gIO6zYQVRw7vWhjETAQ0AAAAAAAAAAAAAAAAAAAAAABI7ua0JZobYs7reCgmqMKt3DZkKVldsd0f94TRMt+AxHba3XkD/PDxXiUhBJ28z3+iQW7B5');
		
		$crypto->decrypt($corrupted, 'clueless');
	}
	
	/**
	 * Test decryption failure due internal error in openssl_decrypt (in this case, due to a too short IV value)
	 * Because of the cipher text is authenticated, it would be quite hard to find a corrupted cipher text in a real world use case
	 */
	public function testCorruptedCipherTextException()
	{
		
		$crypto    = new SymmetricEncryption(12);
		$corrupted = base64_decode('8i/4Tww0RCH/iZOzcYnAXQwAtAMDwN/p+a8DAGWxeA4cKiWNhTnEtbhzDrxkQXEDolUtV+T7A9L6Bwys1w==');
		
		$crypto->decrypt($corrupted, self::PASSWORD); // Warning suppressed because we check the return value
		
		self::assertErrorTriggered(E_WARNING, 'openssl_decrypt(): IV passed is only 11 bytes long, cipher expects an IV of precisely 16 bytes, padding with \0');
	}
	
	/**
	 * Test generic decryption failure
	 */
	public function testGenericDecryptFail()
	{
		self::expectException(Exception::class);
		self::expectExceptionMessage('Failed decrypting the cipher text');
		
		FunctionOverwrites::setActive('openssl_decrypt', false);
		
		$crypto = new SymmetricEncryption(16);
		$crypto->decrypt(base64_decode(self::CIPHER_TEXT), self::PASSWORD);
	}
}
