<?php
namespace Affinity4\Cipher;

class Cipher
{
    /**
     * @var self
     */
    private static $instance;

    /**
     * @var string
     */
    private $cipher;

    /**
     * @var int
     */
    private $options;

    /**
     * --------------------------------------------------
     * Constructor
     * --------------------------------------------------
     * 
     * @author Luke Watts <luke@affinity4.ie>
     * 
     * @since 0.0.1
     */
    public function __construct()
    {
        $this->options = OPENSSL_RAW_DATA;
        $this->cipher = 'AES-128-CBC';
        $this->sha2len = 32;
    }

    /**
     * --------------------------------------------------
     * Encode
     * --------------------------------------------------
     * 
     * @author Luke Watts <luke@affinity4.ie>
     * 
     * @since 0.0.1
     */
    private function encode($encode)
    {
        return base64_encode($encode);
    }

    /**
     * --------------------------------------------------
     * Get Cipher Initialization Vector Length
     * --------------------------------------------------
     * 
     * @author Luke Watts <luke@affinity4.ie>
     * 
     * @since 0.0.1
     */
    private function getCipherInitializationVectorLength()
    {
        return openssl_cipher_iv_length($this->cipher);
    }

    /**
     * --------------------------------------------------
     * Get Encryption Initialization Vector
     * --------------------------------------------------
     * 
     * @author Luke Watts <luke@affinity4.ie>
     * 
     * @since 0.0.1
     */
    private function getEcryptionInitializationVector()
    {
        return openssl_random_pseudo_bytes($this->getCipherInitializationVectorLength());
    }

    /**
     * --------------------------------------------------
     * Get Encrypted Cipher
     * --------------------------------------------------
     * 
     * @author Luke Watts <luke@affinity4.ie>
     * 
     * @since 0.0.1
     */
    private function getEncryptedCipher($str, $key, $iv)
    {
        return openssl_encrypt($str, $this->cipher, $key, $this->options, $iv);
    }

    /**
     * --------------------------------------------------
     * Hash HMAC
     * --------------------------------------------------
     * 
     * @author Luke Watts <luke@affinity4.ie>
     * 
     * @since 0.0.1
     */
    private function hashHMAC($encrypted_cipher, $key)
    {
        $hmac = hash_hmac('sha256', $encrypted_cipher, $key, $as_binary = true);
    }

    /**
     * --------------------------------------------------
     * Encode Cipher
     * --------------------------------------------------
     * 
     * @author Luke Watts <luke@affinity4.ie>
     * 
     * @since 0.0.1
     */
    private function encodeCipher($str, $key)
    {
        $iv = $this->getEcryptionInitializationVector();
        $hmac = hash_hmac('sha256', $this->getEncryptedCipher($str, $key, $iv), $key, $as_binary = true);

        return $this->encode($iv . $hmac . $this->getEncryptedCipher($str, $key, $iv));
    }

    /**
     * --------------------------------------------------
     * Encryption
     * --------------------------------------------------
     * 
     * @param string $str
     * 
     * @param string $key
     * 
     * @author Luke Watts <luke@affinity4.ie>
     * 
     * @since 0.0.1
     */
    public function encryption($str, $key)
    {
        return $this->encodeCipher($str, $key);
    }

    /**
     * --------------------------------------------------
     * Decode
     * --------------------------------------------------
     * 
     * @author Luke Watts <luke@affinity4.ie>
     * 
     * @since 0.0.1
     */
    private function decode($decode)
    {
        return base64_decode($decode);
    }

    /**
     * --------------------------------------------------
     * Get Decryption Initialization Vector
     * --------------------------------------------------
     * 
     * @param string $decode
     * 
     * @author Luke Watts <luke@affinity4.ie>
     * 
     * @since 0.0.1
     */
    private function getDecryptionInitializationVector($decode)
    {
        return  substr($decode, 0, $this->getCipherInitializationVectorLength());
    }

    /**
     * --------------------------------------------------
     * Get HMAC
     * --------------------------------------------------
     * 
     * @author Luke Watts <luke@affinity4.ie>
     * 
     * @since 0.0.1
     */
    private function getHMAC($decode, $ivlen)
    {
        return substr($decode, $ivlen, $this->sha2len);
    }

    /**
     * --------------------------------------------------
     * Get Decrypted
     * --------------------------------------------------
     * 
     * @author Luke Watts <luke@affinity4.ie>
     * 
     * @since 0.0.1
     */
    private function getDecrypted($str, $key)
    {
        $str_raw = substr($this->decode($str), $this->getCipherInitializationVectorLength() + $this->sha2len);

        return openssl_decrypt($str_raw, $this->cipher, $key, $this->options, $this->getDecryptionInitializationVector($this->decode($str)));
    }

    /**
     * --------------------------------------------------
     * Valid Hash
     * --------------------------------------------------
     * 
     * @author Luke Watts <luke@affinity4.ie>
     * 
     * @since 0.0.1
     */
    private function validHash($str, $key)
    {
        $hmac = $this->getHMAC($this->decode($str), $this->getCipherInitializationVectorLength());
        $calcmac = hash_hmac(
            'sha256', 
            substr($this->decode($str), $this->getCipherInitializationVectorLength() + $this->sha2len),
            $key,
            $as_binary = true
        );
    
        return (hash_equals($hmac, $calcmac));
    }

    /**
     * --------------------------------------------------
     * Decryption
     * --------------------------------------------------
     * 
     * @param string $str
     * 
     * @author Luke Watts <luke@affinity4.ie>
     * 
     * @since 0.0.1
     */
    public function decryption($str, $key)
    {
        // PHP 5.6+ timing attack safe comparison
        if ($this->validHash($str, $key)) {
            return $this->getDecrypted($str, $key);
        }

        return false;
    }

    /**
     * --------------------------------------------------
     * Encrypt
     * --------------------------------------------------
     * 
     * @author Luke Watts <luke@affinity4.ie>
     * 
     * @since 0.0.1
     */
    public static function encrypt($str, $key)
    {
        if (self::$instance === null) {
            self::$instance = new self;
        }

        return self::$instance->encryption($str, $key);
    }

    /**
     * --------------------------------------------------
     * Decrypt
     * --------------------------------------------------
     * 
     * @author Luke Watts <luke@affinity4.ie>
     * 
     * @since 0.0.1
     */
    public static function decrypt($str, $key)
    {
        if (self::$instance === null) {
            self::$instance = new self;
        }

        return self::$instance->decryption($str, $key);
    }
}
