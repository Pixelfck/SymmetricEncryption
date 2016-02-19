<?php
namespace Driftwood;

$mockFunctionsActive = array();

function setMockFunctionActive($functionName) {
	global $mockFunctionsActive;
	
	$mockFunctionsActive[$functionName] = true;
}

function getMockFunctionActive($functionName) {
	global $mockFunctionsActive;
	
	if (isset($mockFunctionsActive[$functionName])) {
		unset($mockFunctionsActive[$functionName]);
		return true;
	}
	return false;
}

function ini_get($varName) {
	if (getMockFunctionActive('ini_get')) {
		return MB_OVERLOAD_STRING;
	}
	return \ini_get($varName);
}

function mcrypt_get_iv_size($cipher, $mode) {
	if (getMockFunctionActive('mcrypt_get_iv_size')) {
		return 0;
	}
	return \mcrypt_get_iv_size($cipher, $mode);
}

function hash_hmac($algo, $data, $key, $raw_output) {
	if (getMockFunctionActive('hash_hmac')) {
		return false;
	}
	return \hash_hmac($algo, $data, $key, $raw_output);
}
