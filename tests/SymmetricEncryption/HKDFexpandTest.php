<?php
namespace Tests\SymmetricEncryption;

use Exception;
use Tests\BaseTestCase;
use Driftwood\SymmetricEncryption;
use Netsilik\Testing\Helpers\FunctionOverwrites;


class HKDFexpandTest extends BaseTestCase
{
	/**
	 *
	 */
	public function testWrongKeyLength()
	{
		self::expectException(Exception::class);
		self::expectExceptionMessage('Pseudorandom key is of incorrect length');
		
		$crypto = new SymmetricEncryption(16);
		
		self::callInaccessibleMethod($crypto, '_HKDFexpand', 'abc', 1);
	}
	
	/**
	 *
	 */
	public function testLengthArgumentTooLarge()
	{
		self::expectException(Exception::class);
		self::expectExceptionMessage('length argument must be between 0 and 8160');
		
		$crypto = new SymmetricEncryption(16);
		
		self::callInaccessibleMethod($crypto, '_HKDFexpand', 'abcdefghijabcdefghijabcdefghijab', 10000);
	}
	
	/**
	 *
	 */
	public function testSubstrReturnsFalse()
	{
		self::expectException(Exception::class);
		self::expectExceptionMessage('Failed expanding key to desired length');
		
		FunctionOverwrites::setActive('substr', false);

		$crypto = new SymmetricEncryption(16);
		
		self::callInaccessibleMethod($crypto, '_HKDFexpand', 'abcdefghijabcdefghijabcdefghijab', 100);
	}
	
}
