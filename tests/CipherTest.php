<?php
use PHPUnit\Framework\TestCase;

class CipherTest extends TestCase
{
    /**
     * --------------------------------------------------
     * Test Encrypt and Decrypt
     * --------------------------------------------------
     * 
     * @author Luke Watts <luke@affinity4.ie>
     * 
     * @since 0.0.1
     */
    public function testEncryptDecrypt()
    {
        $key = 'b1f1e6225cb2b6d0230b16125e45ca63';
        $str = 'my secret';

        $encrypted = \Affinity4\Cipher\Cipher::encrypt($str, $key);
        $decrypted = \Affinity4\Cipher\Cipher::decrypt($encrypted, $key);

        $this->assertEquals($decrypted, $str);
    }
}