# eike-grundke/xpub

With this library extended public keys of BTC or ETH network can be derived for any index

`xpub`, `tpub`, `vpub` and `zpub` supported

## Installation

```bash
composer require eike-grundke/xpub
```

### Requirements

* PHP >= 8.1
* BCMath or GMP extension

## Usage

```php
use Grundke\ExtendedPublicKey;
use Grundke\Enum\CoinEnum;
use Grundke\Enum\BipEnmum;

$xPub = ExtendedPublicKey::fromString('xpub...' ; // bip44
$xPub = ExtendedPublicKey::fromString('zpub...'); // bip84 (native SegWit)

// explicit bip
$xPub = ExtendedPublicKey::fromString('xpub...', BipEnmum::BIP84);
$xPub = ExtendedPublicKey::fromString('zpub...', BipEnmum::BIP44);

$xPubFromIndex = $xPub->derive($i);
$xPubFromIndices = $xpub->derive([$i1, $i2]);

// to base58 string
$xPubString = $xPubFromIndex->toString();
// to hex string
$xPubHex = $xPubFromIndex->toString(true);
// to address
$address = $xPubFromIndex->toAddress(CoinEnum::BTC);

# static functions

# hash160
$hash = ExtendedPublicKey::hash160($hex);
# double sha256
$hash = ExtendedPublicKey::doubleSha256($hex);
```