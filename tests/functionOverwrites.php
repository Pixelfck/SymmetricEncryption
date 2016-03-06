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

function openssl_cipher_iv_length($method) {
	if (getMockFunctionActive('openssl_cipher_iv_length')) {
		return 0;
	}
	return \openssl_cipher_iv_length($method);
}

function hash_hmac($algo, $data, $key, $raw_output) {
	if (getMockFunctionActive('hash_hmac')) {
		return false;
	}
	return \hash_hmac($algo, $data, $key, $raw_output);
}

function openssl_random_pseudo_bytes($length, &$crypto_strong = null) {
	if (getMockFunctionActive('openssl_random_pseudo_bytes_readError')) {
		return false;
	} elseif (getMockFunctionActive('openssl_random_pseudo_bytes_qualityFail')) {
		$crypto_strong = false;
		return str_repeat(0, $length);
	}
	return \openssl_random_pseudo_bytes($length, $crypto_strong);
}

function openssl_get_cipher_methods($aliases = false) {
	if (getMockFunctionActive('openssl_get_cipher_methods')) {
		return array();
	}
	return \openssl_get_cipher_methods($aliases);
}

function openssl_decrypt($data, $method, $password, $options = 0, $iv = '') {
	if (getMockFunctionActive('openssl_decrypt')) {
		return false;
	}
	return \openssl_decrypt($data, $method, $password, $options, $iv);
}
