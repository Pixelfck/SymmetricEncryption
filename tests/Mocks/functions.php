<?php

/**
 * Function overwrite for use in namespace Driftwood
 */
namespace Driftwood
{
	
	use Netsilik\Testing\Helpers\FunctionOverwrites;
	
	
	function ini_get(string $varname) : string
	{
		FunctionOverwrites::incrementCallCount(__FUNCTION__);
		
		if (FunctionOverwrites::isActive(__FUNCTION__)) {
			return FunctionOverwrites::shiftNextReturnValue(__FUNCTION__);
		}
		
		return \ini_get($varname);
	}
	
	function openssl_cipher_iv_length(string $method) : int
	{
		FunctionOverwrites::incrementCallCount(__FUNCTION__);
		
		if (FunctionOverwrites::isActive(__FUNCTION__)) {
			return FunctionOverwrites::shiftNextReturnValue(__FUNCTION__);
		}
		
		return \openssl_cipher_iv_length($method);
	}
	
	function hash_hmac(string $algo, string $data, string $key, ?bool $raw_output = false) : string
	{
		FunctionOverwrites::incrementCallCount(__FUNCTION__);
		
		if (FunctionOverwrites::isActive(__FUNCTION__)) {
			return FunctionOverwrites::shiftNextReturnValue(__FUNCTION__);
		}
		
		return \hash_hmac($algo, $data, $key, $raw_output);
	}
	
	function openssl_random_pseudo_bytes(int $length, ?bool &$crypto_strong) // string|false
	{
		FunctionOverwrites::incrementCallCount(__FUNCTION__);
		
		if (FunctionOverwrites::isActive(__FUNCTION__)) {
			$value = FunctionOverwrites::shiftNextReturnValue(__FUNCTION__);
			
			if ('readError' === $value) {
				return false;
			}
			
			if ('qualityFail' === $value) {
				$crypto_strong = false;
				
				return str_repeat(0, $length);
			}
			
			return $value;
		}
		
		return \openssl_random_pseudo_bytes($length, $crypto_strong);
	}
	
	function openssl_get_cipher_methods(?bool $aliases = false) : array
	{
		FunctionOverwrites::incrementCallCount(__FUNCTION__);
		
		if (FunctionOverwrites::isActive(__FUNCTION__)) {
			return FunctionOverwrites::shiftNextReturnValue(__FUNCTION__);
		}
		
		return \openssl_get_cipher_methods($aliases);
	}
	
	function openssl_decrypt(string $data, string $method, string $key, ?int $options = 0, ?string $iv = '', ?string $tag = '', ?string $aad = '') // string|false
	{
		FunctionOverwrites::incrementCallCount(__FUNCTION__);
		
		if (FunctionOverwrites::isActive(__FUNCTION__)) {
			return FunctionOverwrites::shiftNextReturnValue(__FUNCTION__);
		}
		
		return \openssl_decrypt($data, $method, $key, $options, $iv, $tag, $aad);
	}
}
