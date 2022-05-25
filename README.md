# Affinity4 Cipher

Encrypt and decrypt private strings. Useful if you need to store a string as a hash but need to see it as plain text also.

__DO NOT USE FOR PASSWORD AUTHENTICATION!__

## Installation

### Composer

```bash
composer require affinity4/cipher
```

## Usage

```php
// Used by both excrypt and decrypt methods, so should be available globally
// Perhaps as an environment variable
$key = 'b1f1e6225cb2b6d0230b16125e45ca63';
$str = 'my secret';

$encrypted = \Affinity4\Cipher\Cipher::encrypt($str, $key); // piqwpeiqep12801aqwie0248quqjowq==
$decrypted = \Affinity4\Cipher\Cipher::decrypt($encrypted, $key); // my secret
```

## Licence

MIT 2018 Luke Watts
