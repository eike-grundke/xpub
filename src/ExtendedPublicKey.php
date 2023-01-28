<?php

namespace Grundke;

use BitWasp\Bech32\Exception\Bech32Exception;
use Exception;
use Grundke\Enum\BipEnum;
use Grundke\Enum\CoinEnum;
use Grundke\Enum\HexVersionEnum;
use Grundke\Exception\XPubException;
use StephenHill\Base58;
use Elliptic\EC;
use BN\BN;
use kornrunner\Keccak;
use BitWasp\Bech32;

/**
 * Derivation of extended public keys
 * for BTC and ETH networks
 *
 * @see https://rosenbaum.se/book/grokking-bitcoin-4.html#extended-public-keys
 * @author Eike Grundke <me@eikegrundke.de>
 */
class ExtendedPublicKey
{
    public const SEGWIT_VERSION = 0;

    public function __construct(
        protected HexVersionEnum $hexVersion,
        protected int            $depth,
        protected string         $parentFingerprint,
        protected int            $index,
        protected string         $c,
        protected string         $k
    )
    {
    }

    /**
     * @throws XPubException
     */
    public static function fromString(string $xPubBase58, ?BipEnum $bip = null): ExtendedPublicKey
    {
        $prefix = substr($xPubBase58, 0, 4);

        $hexVersion = $bip ? $bip->toHexVersion($prefix) : HexVersionEnum::fromPrefix($prefix);

        $xPubBin = (new Base58())->decode($xPubBase58);

        if (strlen($xPubBin) !== 78 && strlen($xPubBin) !== 82) {
            throw new XPubException('invalid length');
        }

        $depth = self::bin2dec(substr($xPubBin, 4, 1));
        $parentFingerprint = bin2hex(substr($xPubBin, 5, 4));
        $index = self::bin2dec(substr($xPubBin, 9, 4));
        $c = bin2hex(substr($xPubBin, 13, 32));
        $k = bin2hex(substr($xPubBin, 45, 33));

        $checksum = substr($xPubBin, 78, 4);
        if ($checksum) {
            $baseXPubHex = bin2hex(substr($xPubBin, 0, 78));
            if (substr(self::doubleSha256($baseXPubHex), 0, 8) !== bin2hex($checksum)) {
                throw new XPubException('invalid checksum');
            }
        }

        return new self(
            $hexVersion,
            $depth,
            $parentFingerprint,
            $index,
            $c,
            $k
        );
    }

    public static function bin2dec(string $bin): int
    {
        return unpack('C', $bin)[1];
    }

    public static function hash160(string $hex): string
    {
        return hash('ripemd160', hash('sha256', hex2bin($hex), true));
    }

    public static function doubleSha256(string $hex): string
    {
        return hash('sha256', hash('sha256', hex2bin($hex), true));
    }

    /**
     * @throws Exception
     * @see https://rosenbaum.se/book/grokking-bitcoin-4.html#extended-public-keys
     */
    public function derive(array|int $indices): ExtendedPublicKey
    {
        if (!is_array($indices)) {
            $indices = [$indices];
        }

        $index = array_shift($indices);

        $ellipticCurve = new EC('secp256k1'); // Bitcoin elliptic curve

        $key = hex2bin($this->c);
        $data = hex2bin($this->k) . pack('N', $index);

        $i = hash_hmac('sha512', $data, $key);
        $iL = substr($i, 0, 64);
        $iR = substr($i, 64, 64);

        $kParPoint = $ellipticCurve->curve->decodePoint($this->k, 'hex');
        $iLPoint = $ellipticCurve->g->mul(new BN($iL, 16));

        $kI = $kParPoint->add($iLPoint)->encodeCompressed('hex');

        $parentFingerprint = substr(self::hash160($this->k), 0, 8);

        $child = new self(
            $this->hexVersion,
            $this->depth + 1,
            $parentFingerprint,
            $index,
            $iR,
            $kI
        );

        if (count($indices) > 0) {
            return $child->derive($indices);
        }

        return $child;
    }

    public function toString(bool $asHex = false): string
    {
        $xPubHex = $this->hexVersion->value;
        $xPubHex .= str_pad(dechex($this->depth), 2, '0', STR_PAD_LEFT);
        $xPubHex .= $this->parentFingerprint;
        $xPubHex .= str_pad(dechex($this->index), 8, '0', STR_PAD_LEFT);
        $xPubHex .= $this->c;
        $xPubHex .= $this->k;

        // checksum
        $xPubHex .= substr(self::doubleSha256($xPubHex), 0, 8);

        if ($asHex) {
            return $xPubHex;
        }

        return (new Base58())->encode(hex2bin($xPubHex));
    }

    /**
     * @throws Bech32Exception
     * @throws XPubException
     * @throws Exception
     */
    public function toAddress(CoinEnum $coin = CoinEnum::BTC): string
    {
        return match ($coin) {
            CoinEnum::BTC => $this->toBTCAddress(),
            CoinEnum::ETH => $this->toETHAddress(),
        };
    }

    /**
     * @throws Bech32Exception
     * @throws XPubException
     */
    public function toBtcAddress(): string
    {
        return match ($this->hexVersion) {
            HexVersionEnum::XPUB, HexVersionEnum::TPUB => $this->toBtcP2PKhAddress(),
            HexVersionEnum::VPUB, HexVersionEnum::ZPUB => $this->toBtcP2WpkhAddress()
        };
    }

    /**
     * @throws XPubException
     */
    private function getNetworkId(): string
    {
        return match ($this->hexVersion) {
            HexVersionEnum::TPUB => '6f',
            HexVersionEnum::XPUB => '00',
            HexVersionEnum::VPUB, HexVersionEnum::ZPUB => throw new XPubException('invalid hex version'),
        };
    }

    /**
     * @throws XPubException
     */
    private function getSegwitHrp(): string
    {
        return match ($this->hexVersion) {
            HexVersionEnum::VPUB => 'tc',
            HexVersionEnum::ZPUB => 'bc',
            HexVersionEnum::TPUB, HexVersionEnum::XPUB => throw new XPubException('invalid hex version'),
        };
    }

    /**
     * @throws XPubException
     */
    private function toBtcP2PKhAddress(): string
    {
        $baseAddress = $this->getNetworkId() . self::hash160($this->k);
        $checksum = substr(self::doubleSha256($baseAddress), 0, 8);
        $addressHex = $baseAddress . $checksum;

        return (new Base58())->encode(hex2bin($addressHex));
    }

    /**
     * @throws Bech32Exception
     * @throws XPubException
     */
    private function toBtcP2WpkhAddress(): string
    {
        $programm = self::hash160($this->k);
        $version = self::SEGWIT_VERSION;
        $hrp = $this->getSegwitHrp();
        return Bech32\encodeSegwit($hrp, $version, hex2bin($programm));
    }

    /**
     * @throws Exception
     */
    private function toETHAddress(): string
    {
        $ellipticCurve = new EC('secp256k1');

        $kFull = $ellipticCurve->keyFromPublic($this->k, 'hex')->getPublic('hex');

        $kBin = hex2bin(substr($kFull, 2));
        $hashHex = Keccak::hash($kBin, 256);
        $baseAddress = substr($hashHex, 24, 40);

        return '0x' . $this->encodeETHChecksum($baseAddress);
    }

    /**
     * @throws Exception
     */
    private function encodeETHChecksum(string $baseAddress): string
    {
        $binary = $this->hex2binary(Keccak::hash($baseAddress, 256));

        $encoded = '';
        foreach (str_split($baseAddress) as $i => $char) {
            if (str_contains('abcdef', $char)) {
                $encoded .= $binary[$i * 4] === '1' ? strtoupper($char) : strtolower($char);
            } else {
                $encoded .= $char;
            }
        }
        return $encoded;
    }

    private function hex2binary($hex): string
    {
        $binary = '';
        foreach (str_split($hex, 2) as $hexit) {
            $binary .= str_pad(decbin(hexdec($hexit)), 8, '0', STR_PAD_LEFT);
        }
        return $binary;
    }
}
