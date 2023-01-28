<?php

namespace Grundke\Enum;

enum BipEnum: string
{
    case BIP44 = 'bip-44';
    case BIP84 = 'bip-84';

    public function toHexVersion(string $prefix): HexVersionEnum
    {
        return match ($this) {
            self::BIP44 => in_array($prefix, ['xpub', 'zpub']) ? HexVersionEnum::XPUB : HexVersionEnum::TPUB,
            self::BIP84 => in_array($prefix, ['xpub', 'zpub']) ? HexVersionEnum::ZPUB : HexVersionEnum::VPUB
        };
    }
}
