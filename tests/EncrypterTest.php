<?php

declare(strict_types=1);

namespace Tests;

use Tym\Encryption\Encrypter;
use PHPUnit\Framework\TestCase;

final class EncrypterTest extends TestCase
{
    private Encrypter $encrypter;

    protected function setUp(): void
    {
        $this->encrypter = new Encrypter;
    }

    public function testEncrypt()
    {
        $data = "Yvan Tchuente";
        $key = Encrypter::generateKey();
        $cipherText = $this->encrypter->encrypt($data, $key);
        $this->assertNotEmpty($cipherText);

        return ['cipherText' => $cipherText, 'key' => $key];
    }

    /**
     * @depends testEncrypt
     */
    public function testDecrypt(array $results)
    {
        $data = $this->encrypter->decrypt($results['cipherText'], $results['key']);
        $this->assertNotEmpty($data);
    }

    public function testAuthenticatedEncryption()
    {
        $data = "Yvan Tchuente";
        $key = Encrypter::generateKey();
        $options = ['authenticate' => true];
        $result = $this->encrypter->encrypt($data, $key, $options);
        $this->assertIsArray($result);
        $this->assertArrayHasKey("cipherText", $result);
        $this->assertArrayHasKey("iv", $result);
        $this->assertArrayHasKey("tag", $result);

        return array_merge($result, ['key' => $key]);
    }

    /**
     * @depends testAuthenticatedEncryption
     */
    public function testAuthenticatedDecryption(array $results)
    {
        $cipherText = array_shift($results);
        $key = $results['key'];
        $data = $this->encrypter->decrypt(
            $cipherText,
            $results['key'],
            [
                'iv' => $results['iv'],
                'tag' => $results['tag']
            ]
        );
        $this->assertNotEmpty($data);
    }

    public function testDetectsEmptyData()
    {
        $data = "";
        $key = Encrypter::generateKey();
        $this->expectException(\LengthException::class);
        $this->encrypter->encrypt($data, $key);
    }

    public function testGenerateKey()
    {
        $key = Encrypter::generateKey('aes-256-xts');
        $this->assertNotEmpty($key);
    }

    public function testDetectsUnkonwnCipher()
    {
        $this->expectException(\DomainException::class);
        Encrypter::generateKey('aes-256-octs');
    }

    public function testDetectsInvalidKey()
    {
        $data = "Yvan Tchuente";
        $key = random_bytes(16);
        $this->expectExceptionMessage("The key is not base64-encoded.");
        $this->encrypter->encrypt($data, $key);
    }

    public function testDetectsInvalidTag()
    {
        $data = "Yvan Tchuente";
        $key = random_bytes(16);
        $this->expectExceptionMessage("The key is not base64-encoded.");
        $this->encrypter->encrypt($data, $key);
    }

    public function testDetectsInvalidOptions()
    {
        $data = "Yvan Tchuente";
        $key = Encrypter::generateKey();

        $options = ['use_iv' => 'yes'];
        $this->expectException(\LogicException::class);
        $this->encrypter->encrypt($data, $key, $options);

        $options = ['authenticate' => 'no'];
        $this->expectException(\LogicException::class);
        $this->encrypter->encrypt($data, $key, $options);
    }
}
