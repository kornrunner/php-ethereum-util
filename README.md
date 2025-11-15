# php-ethereum-util [![Tests](https://github.com/kornrunner/php-ethereum-util/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/kornrunner/php-ethereum-util/actions/workflows/tests.yml) [![Coverage Status](https://coveralls.io/repos/github/kornrunner/php-ethereum-util/badge.svg?branch=master)](https://coveralls.io/github/kornrunner/php-ethereum-util?branch=master) [![Latest Stable Version](https://poser.pugx.org/kornrunner/ethereum-util/v/stable)](https://packagist.org/packages/kornrunner/ethereum-util)

Pure PHP implementation of Ethereum Utils

## Usage

### Hash Personal Message

```php
use kornrunner\Eth;

$hash = Eth::hashPersonalMessage('0xf20f20d357419f696f69e6ff05bc6566b1e6d38814ce4f489d35711e2fd2c481');
// 58a2db04c169254495a55b6dd5609a4902678ec29eac46df1e95994cdbeaebbb
```

### Sign Personal Message

```php
use kornrunner\Eth;

$result = Eth::signPersonalMessage('Hello, Ethereum!', $privateKey);
```

### Recover Public Key from Signature (ecRecover)

```php
use kornrunner\Eth;

$publicKey = Eth::ecRecover(
    '98d22cdb65bbf8a392180cd2ee892b0a971c47e7d29daf31a3286d006b9db4dc',
    'f67118680df5993e8efca4d3ecc4172ca4ac5e3e007ea774293e373864809703',
    '47427f3633371c1a30abbb2b717dbd78ef63d5b19b5a951f9d681cccdd520320',
    0
);
```

### Verify Signature (ecVerify)

```php
use kornrunner\Eth;

$isValid = Eth::ecVerify(
    '98d22cdb65bbf8a392180cd2ee892b0a971c47e7d29daf31a3286d006b9db4dc', // message hash
    'f67118680df5993e8efca4d3ecc4172ca4ac5e3e007ea774293e373864809703', // r component
    '47427f3633371c1a30abbb2b717dbd78ef63d5b19b5a951f9d681cccdd520320', // s component
    0, // recovery id (v)
    '04cf60398ae73fd947ffe120fba68947ec741fe696438d68a2e52caca139613ff94f220cd0d3e886f95aa226f2ad2b86be1dd5cda2813fd505d1f6a8f552904864' // public key
);
// true
```

All methods support both plain hex strings and 0x-prefixed hex strings.

## Crypto

[![Ethereum](https://user-images.githubusercontent.com/725986/61891022-0d0c7f00-af09-11e9-829f-096c039bbbfa.png) 0x9c7b7a00972121fb843af7af74526d7eb585b171][Ethereum]

[Ethereum]: https://etherscan.io/address/0x9c7b7a00972121fb843af7af74526d7eb585b171 "Donate with Ethereum"
