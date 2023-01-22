<?php

declare(strict_types=1);

namespace Tym\Encryption;

/**
 * @author Yvan Tchuente <yvantchuente@gmail.com>
 */
class Encrypter
{
    /**
     * An array of encryption options keyed by their value type.
     * 
     * @var string[][]
     */
    private array $options = [
        'boolean' => ['authenticate', 'use_iv'],
        'string' => ['aad', 'iv', 'tag']
    ];

    /**
     * The supported cipher algorithms and their properties.
     */
    private array $ciphers = [
        'normal' => 'aes-256-xts',
        'authenticated' => 'aes-256-gcm'
    ];

    /**
     * Creates a new encryption key.
     * 
     * @return string The key base64-encoded.
     */
    public static function generateKey(string $cipher = null)
    {
        if (!is_null($cipher)) {
            if (!in_array(strtolower($cipher), openssl_get_cipher_methods())) {
                throw new \DomainException("Unknown cipher method.");
            }
            $length = openssl_cipher_iv_length($cipher);
        }

        return base64_encode(random_bytes($length ?? 16));
    }

    /**
     * Encrypts a piece of data.
     * 
     * Encryption options include:
     * 
     * | Option         | Type          | Description                                                       | Comment                                               |
     * | :---           | :---          | :---                                                              | :---                                                  |
     * | use_iv         | boolean       | Tell whether to use an initialization vector during encryption.   | It is implicitly set to **true** if `authenticate`    |
     * |                |               |                                                                   | is set to set to **true** otherwise it defaults to    |
     * |                |               |                                                                   | **false**.                                            |
     * | authenticate   | boolean       | Tell whether to use authenticate the encryption process.          | Defaults to **false**.                                |                        |
     * | aad            | string        | Additional authentication data for authenticated encryption.      |                                                       |
     * 
     * The possible elements of the resulting array that may be returned include:
     * 
     * | Key            | Description                                           | Comment                                           |
     * | :---           | :---                                                  | :---                                              |
     * | cipherText     | The encrypted piece of data.                          |                                                   |
     * | iv             | The generated initialization vector base64-encoded.   | Present only if the **`use_iv`** option was set   |
     * |                |                                                       | to **true**.                                      |
     * | tag            | The generated authentication tag base64-encoded.      | Present only if the **`authenticate`** option     |
     * |                |                                                       | was set to **true**.                              |
     * 
     * @param string $data The piece of data
     * @param string $key The base64-encoded key 
     * @param array $options A name / value list of encryption options
     * 
     * @return string|array The ciphertext or an array of encryption results.
     * 
     * @throws \LogicException
     */
    public function encrypt(string $data, string $key, array $options = [])
    {
        if (!$data) {
            throw new \LengthException("The data to encrypt is empty.");
        }
        if (!self::isBase64Encoded($key)) {
            throw new \LogicException("The key is not base64-encoded.");
        }

        $this->validateOptions($options, __FUNCTION__);
        $this->setOptionDefaults($options);

        $cipher = ($options['authenticate']) ? $this->ciphers['authenticated'] : $this->ciphers['normal'];
        $iv_length = openssl_cipher_iv_length($cipher);
        $data = $this->standardize($data, $iv_length);
        $key = base64_decode($key);
        $iv = ($options['use_iv']) ? random_bytes($iv_length) : '';

        // Encrypt
        if ($options['authenticate']) {
            $value = @openssl_encrypt($data, $cipher, $key, 0, $iv, $tag, $options['aad']);
        } else {
            $value = @openssl_encrypt($data, $cipher, $key, 0, $iv);
        }

        if ($value === false) {
            throw new EncryptionException("The encryption failed.");
        }

        switch (true) {
            case ($options['use_iv']):
                $result = ['cipherText' => $value, 'iv' => base64_encode($iv)];
            case ($options['authenticate'] and isset($tag)):
                $result['tag'] = base64_encode($tag);
                break;
            default:
                $result = $value;
                break;
        }

        return $result;
    }

    /**
     * Decrypts a ciphertext.
     * 
     * The possible decryption options include:
     * 
     * | Option         | Type          | Description                                                   |
     * | :---           | :---          | :---                                                          |
     * | iv             | boolean       | The base64-encoded initialization vector for decryption.      |
     * | tag            | string        | The base64-encoded authentication tag for authenticated       |
     * |                |               | decryption.                                                   |
     * | aad            | string        | Additional authentication data for authenticated decryption.  |
     * 
     * @param string $ciphertext The encrypted piece of data
     * @param string $key The base64-encoded key 
     * @param array $options A name / value list of decryption options
     * 
     * @return string The decrypted data.
     * 
     * @throws \LogicException
     */
    public function decrypt(string $ciphertext, string $key, array $options = [])
    {
        if (!$ciphertext) {
            throw new \LengthException("The ciphertext is empty.");
        }
        if (!self::isBase64Encoded($key)) {
            throw new \LogicException("The key is not base64-encoded.");
        }
        if (isset($options['tag']) and !self::isBase64Encoded($options['tag'])) {
            throw new \InvalidArgumentException("The authentication tag is not base64-encoded");
        }

        $this->validateOptions($options, __FUNCTION__);
        $this->setOptionDefaults($options);

        $cipher = ($options['tag']) ? $this->ciphers['authenticated'] : $this->ciphers['normal'];
        $iv_length = openssl_cipher_iv_length($cipher);
        $key = base64_decode($key);

        if ($options['iv']) {
            if (!self::isBase64Encoded($options['iv'])) {
                throw new \InvalidArgumentException("The initialization vector is not base64-encoded");
            }
            if (strlen(base64_decode($options['iv'])) !== $iv_length) {
                throw new \InvalidArgumentException(sprintf("The initialization vector must be %d bytes long, actual length is %d", $iv_length, strlen(base64_decode($$options['iv']))));
            }
            $options['iv'] = base64_decode($options['iv']);
        }
        $iv = $options['iv'];

        // Decrypt
        if ($options['tag']) {
            $tag = base64_decode($options['tag']);
            $data = @openssl_decrypt($ciphertext, $cipher, $key, 0, $iv, $tag, $options['aad']);
        } else {
            $data = @openssl_decrypt($ciphertext, $cipher, $key, iv: $iv);
        }

        if ($data === false) {
            throw new DecryptionException("The decryption failed.");
        }

        return $data;
    }

    private function standardize(string $data, int $iv_length)
    {
        if (strlen($data) < $iv_length) {
            $data = str_pad($data, $iv_length);
        }
        return $data;
    }

    /**
     * Validates all given options.
     * 
     * @throws \LogicException
     */
    private function validateOptions(array $options, string $method)
    {
        $method = ucfirst(strtolower($method)) . "ion";
        $exception = __NAMESPACE__ . "\\" . $method . "Exception";

        foreach ($options as $name => $value) {
            foreach ($this->options as $type => $option_group) {
                if (in_array($name, $option_group, true)) {
                    $found = true;
                    if (gettype($value) === $type) {
                        $validType = true;
                        break;
                    } else {
                        $validType = false;
                    }
                } else {
                    $found = false;
                }
            }
            if (!$found) {
                throw new $exception(
                    sprintf(
                        "%s is not a valid %s option.",
                        $name,
                        strtolower($method)
                    )
                );
            }
            if (!$validType) {
                throw new $exception("Invalid value type for '$name' $method option.");
            }
        }
    }

    /**
     * Set options missing in the given list of options to their
     * default values.
     */
    private function setOptionDefaults(array &$options)
    {
        foreach ($this->options as $type => $option_group) {
            foreach ($option_group as $option) {
                if (!isset($options[$option])) {
                    switch ($type) {
                        case 'boolean':
                            $options[$option] = false;
                            break;
                        case 'string':
                            $options[$option] = '';
                            break;
                    }
                }
            }
        }

        // Implicitly set certain options based on some conditions
        if ($options['authenticate']) {
            $options['use_iv'] = true;
        }
    }

    /**
     * Determines if a piece of data is base64 encoded.
     */
    public static function isBase64Encoded(string $data)
    {
        try {
            return (isset($data)) ? (base64_encode(base64_decode($data, true)) === $data) : false;
        } catch (\Throwable $e) {
            return false;
        }
    }
}
