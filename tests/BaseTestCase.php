<?php
namespace Tests;

/**
 * This file is copyright protected. It is not
 * allowed to adjust, reproduce or sell this
 * product without approval from the author.
 */

use Netsilik\Testing\BaseTestCase AS NetsilikBaseTestCase;


abstract class BaseTestCase extends NetsilikBaseTestCase
{
	/**
	 * {@inheritDoc}
	 */
	public function __construct($name = null, array $data = [], $dataName = '')
	{
		parent::__construct($name, $data, $dataName);
		
		$this->_convertNoticesToExceptions  = false;
		$this->_convertWarningsToExceptions = false;
		$this->_convertErrorsToExceptions   = true;
	}
}
