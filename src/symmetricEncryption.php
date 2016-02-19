<?php
namespace Driftwood;

/**
 * @version 1.0.3
 * @license EUPL (European Union Public Licence, v.1.1)
 * 
 * Example of usage:
 * 
 *   $password = 'correct horse battery staple';
 *   $crypto = new SymmetricEncryption(20);
 *   $encrypted = $crypto->encrypt('Never roll your own crypto.', $password);
 *   $decrypted = $crypto->decrypt($encrypted, $password);
 *   echo $decrypted; // Never roll your own crypto.
 */

 
/**
 * A class which makes Symmetric Encryption easy by encapsulating all the choices
 * configuration options into a single class.
 */
class SymmetricEncryption {
	
	/**
	 * Algorithm to use in the key derivation function
	 */
	const PBKDF2_HASH_ALGORITHM = 'sha256';
	
	/**
	 * Minimum number of 2^iteration to use when deriving key from password
	 */
	const PBKDF2_ITERATIONS_LOG2_MINIMUM = 12;
	
	/**
	 * The number of random bytes to use as a salt
	 * 128 bits should be large with safety margin to spare
	 */
	const PBKDF2_SALT_LENGTH = 16;
	
	/**
	 * Block count is based on desired length for derived key.
	 * In case of password hashing, the optimal key length is equal to the output size of the selected hash
	 * algorithm, which results in a block count of 1.
	 * The reason for this is that RFC2898 section 5.2, in the PBKDF2 definition, specifies that if more 
	 * output bytes (dkLen) are requested than the native hash function supplies, you do a full iteration 
	 * count for the first native hash size, then another full iteration count for the second, and continue
	 * until you're done or you have to truncate the output because the remainder of what you need is less than
	 * the native output size.
	 */
	const PBKDF2_BLOCK_COUNT = 1;
	
	/**
	 * Algorithm to use in the key stretching function
	 */
	const HKDF_HASH_ALGORITHM = 'sha256';
	
	/**
	 * Output length in bytes for the key stretching hash algorithm
	 */
	const HKDF_HASH_BYTE_LENGtH = 32;
	
	/**
	 * Algorithm to use for the symmetric encryption
	 */
	const CIPHER_ALGORITHM = MCRYPT_RIJNDAEL_128; // Rijndael with 128 bits block size == AES
	
	/**
	 * Length in bytes for key used by the cipher algorithm. We want AES-128 (AES with a key size of 128 bits)
	 */
	const CIPHER_KEY_LENGTH = 16;
	
	/**
	 * Cipher mode of operation to use
	 * CTR mode would be better (and safe us a lot of work), but is unfortunately not supported by PHP's mcrypt module
	 */
	const CIPHER_MODE = MCRYPT_MODE_CFB;
	
	/**
	 * Constant string for key stretching into cipher key
	 */
	const CIPHER_KEY_INFO = 'EncryptionKey'; 
	
	/**
	 * Algorithm to use for authentication
	 */
	const HMAC_HASH_ALGORITHM = 'sha256';
	
	/**
	 * Length of the key in bytes to use for authentication 
	 */
	const HMAC_KEY_LENGTH = 32; 
	
	/**
	 * Constant string for key stretching into hmac key
	 */
	const HMAC_KEY_INFO = 'AuthenticationKey'; 
	
	/**
	 * @var integer $_ivLength length of initialisation vector for this algorithm and mode
	 */
	private $_ivLength = 0;
	
	
	/**
	 * @var integer $_hmacLength output length of the authentication hash algorithm in bytes
	 */
	private $_hmacLength = 0;
	
	/**
	 * The two to the power of iterations number of iterations to perform on the key derivation step
	 * 2^12 iterations is an acceptable lower limit
	 */
	private $_pbkdf2IterationsLog2 = self::PBKDF2_ITERATIONS_LOG2_MINIMUM;
	
	/**
	 * @param integer $keyDerivationIterationsLog2 The number of iterations to perform when stretching the key
	 */
	public function __construct($keyDerivationIterationsLog2 = self::PBKDF2_ITERATIONS_LOG2_MINIMUM) {
		if (0 <> (ini_get('mbstring.func_overload') & MB_OVERLOAD_STRING)) {
			trigger_error('Incompatible Multibyte String functions overloading detected', E_USER_ERROR);
		}
		
		if ($keyDerivationIterationsLog2 < self::PBKDF2_ITERATIONS_LOG2_MINIMUM) {
			trigger_error('Number of iterations used for key stretching is too low, using default instead', E_USER_WARNING);
		} else {
			$this->_pbkdf2IterationsLog2 = $keyDerivationIterationsLog2;
		}
		
		$this->_ivLength = mcrypt_get_iv_size(self::CIPHER_ALGORITHM, self::CIPHER_MODE);
		if (false === $this->_ivLength || 0 >= $this->_ivLength) {
			trigger_error('Could not determine IV size', E_USER_ERROR);
		}
		
		$this->_hmacLength = strlen(hash_hmac(self::HMAC_HASH_ALGORITHM, '', '', true));
		if (0 >= $this->_hmacLength) {
			trigger_error('Could not determine authentication algorithm output size', E_USER_ERROR);
		}
	}

	/**
	 * Encrypt and authenticate plaintext data
	 * @param string $plainText
	 * @param string $password
	 * @return string unecrypted data
	 */
	public function encrypt($plainText, $password) {
		
		// step 1: derive a key from the password
		$salt = $this->_fetchRandomBytes(self::PBKDF2_SALT_LENGTH);
		$derivedKey = $this->_PBKDF2($password, $salt, $this->_pbkdf2IterationsLog2);
		$iterationsLog2 = pack('s', $this->_pbkdf2IterationsLog2);
		
		// step 2: stretch derived key for encryption and authentication
		$cipherKey = $this->_HKDFexpand($derivedKey, self::CIPHER_KEY_LENGTH, self::CIPHER_KEY_INFO);
		$hmacKey = $this->_HKDFexpand($derivedKey, self::HMAC_KEY_LENGTH, self::HMAC_KEY_INFO);
		
		// step 3: encrypt the data
		$iv = $this->_fetchRandomBytes($this->_ivLength);
		$cipherText = mcrypt_encrypt(self::CIPHER_ALGORITHM, $cipherKey, $plainText, self::CIPHER_MODE, $iv);
		
		// step 4: authenticate the concatenated salt, IV and encrypted data
		$data = $salt.$iterationsLog2.$iv.$cipherText;
		$hmac = hash_hmac(self::HMAC_HASH_ALGORITHM, $data, $hmacKey, true);
		
		return $data.$hmac;
	}

	/**
	 * Check authentication and decrypt encrypted data
	 * @param string $cipherText
	 * @param string $password
	 * @throws Exception
	 * @return decrypted data
	 */
	public function decrypt($cipherText, $password) {
		// step 1: find pbkdf2 salt and compute the derived key
		$salt = substr($cipherText, 0, self::PBKDF2_SALT_LENGTH);
		$iterationsLog2 = unpack('s', substr($cipherText, self::PBKDF2_SALT_LENGTH, 2));
		if ($iterationsLog2[1] > $this->_pbkdf2IterationsLog2) {
			throw new \Exception('PBKDF2 iterations out of bounds');
		}
		$derivedKey = $this->_PBKDF2($password, $salt, $iterationsLog2[1]);
		
		// step 2: stretch derived key for encryption and authentication
		$cipherKey = $this->_HKDFexpand($derivedKey, self::CIPHER_KEY_LENGTH, self::CIPHER_KEY_INFO);
		$hmacKey = $this->_HKDFexpand($derivedKey, self::HMAC_KEY_LENGTH, self::HMAC_KEY_INFO);
		
		// step 3: verify the authentication
		$hmac = substr($cipherText, - $this->_hmacLength);
		$authenticatedData = substr($cipherText, 0, - $this->_hmacLength);
		
		if ( !$this->_constantTimeCompare($hmac, hash_hmac(self::HMAC_HASH_ALGORITHM, $authenticatedData, $hmacKey, true)) ) {
			throw new \Exception('Signature verification failed!');
		}
		
		// step 4: decrypt the data
		$iv = substr($authenticatedData, self::PBKDF2_SALT_LENGTH + 2, $this->_ivLength);
		$cipherText = substr($authenticatedData, self::PBKDF2_SALT_LENGTH + 2 + $this->_ivLength);
		if ( false === ($plainText = mcrypt_decrypt(self::CIPHER_ALGORITHM, $cipherKey, $cipherText, self::CIPHER_MODE, $iv)) ) {
			throw new \Exception('Failed decrypting the cipher text');
		}
		
		return $plainText;
	}
	
	/**
	 * Constant time string comparison function
	 * @param string $strA
	 * @param string $strB
	 * @return bool true if parameters $strA and $strB are equal, false otherwise
	 */
	private function _constantTimeCompare($strA, $strB) {
		$lengthA = strlen($strA);
		$lengthB = strlen($strB);
		$minLength = min($lengthA, $lengthB);
		
		$result = $lengthA ^ $lengthB;
		for ($i = 0; $i < $minLength; $i++) {
			$result |= ord($strA{$i}) ^ ord($strB{$i});
		}
		return (0 === $result);	
	}
	
	/**
	 * Fetch random bytes
	 * @param integer $length the required number of bytes to fetch
	 * @return string $iv random bytes
	 */
	private function _fetchRandomBytes($length) {
		if ( false === ($random = mcrypt_create_iv($length, MCRYPT_DEV_URANDOM)) ) {
			trigger_error('Could not read random data', E_USER_ERROR);
		}
		return $random;
	}
	
	/**
	 * Stretch a key into a longer key (see: http://tools.ietf.org/html/rfc5869)
	 * Note: only the HKDF-Expand step is used here; the HKDF-Extract step has been replaced by PBKDF2
	 * @param string $pseudoRandomKey a pseudo random key of at least self::HKDF_HASH_BYTE_LENGtH bytes in length
	 * @param integer $length the desired length of the output in bytes
	 * @param string $info optional string to feed into the algorithm as to differentiate the results
	 * @return string the stretched result of desired length of pseudo random bytes
	 */
	private function _HKDFexpand($pseudoRandomKey, $length, $info = '') {
		// Sanity-check the desired output length.
		if (strlen($pseudoRandomKey) < self::HKDF_HASH_BYTE_LENGtH) {
			trigger_error('Pseudorandom key is of incorrect length', E_USER_ERROR);
		}
		if ( !is_int($length) || 0 > $length || 255 * self::HKDF_HASH_BYTE_LENGtH < $length) {
			trigger_error('length argument must be between 0 and '.(255 * self::HKDF_HASH_BYTE_LENGtH), E_USER_ERROR);
		}
		
		// Expand the Pseudo Random Key into Output Keying Material
		$t = '';
		$last = '';
		for ($i = 1; strlen($t) < $length; $i++) {
			$last = hash_hmac(self::HKDF_HASH_ALGORITHM, $last . $info . chr($i), $pseudoRandomKey, true);
			$t .= $last;
		}
		
		// Slice Output Keying Material to desired length
		if ( false === ($outputKey = substr($t, 0, $length)) ) {
			trigger_error('Failed expanding key to desired length', E_USER_ERROR);
		}
		return $outputKey;
	}
	
	/**
	 * Derive a cryptograpic key from a password (see: https://tools.ietf.org/html/rfc2898)
	 * @param string $password the password to derive a key from
	 * @param string $salt the salt to use in the derivation process
	 * @return a cryptographic key derived from the password and salt
	 */
	private function _PBKDF2($password, $salt, $iterationsLog2) {
		$derivedKey = '';
		$iterationCount = pow(2, $iterationsLog2);
		for($i = 1; $i <= self::PBKDF2_BLOCK_COUNT; $i++) {
			$last = $salt . pack('N', $i); // $i encoded as 4 bytes, big endian.
			
			$last = $xorSum = hash_hmac(self::PBKDF2_HASH_ALGORITHM, $last, $password, true); // first iteration
			for ($j = 1; $j < $iterationCount; $j++) { // perform $iterationCount - 1 iterations
				$xorSum ^= ($last = hash_hmac(self::PBKDF2_HASH_ALGORITHM, $last, $password, true));
			}
			
			$derivedKey .= $xorSum;
		}
		
		return $derivedKey;
	}
}
