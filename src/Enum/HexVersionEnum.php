<?php

namespace Grundke\Enum;

use Grundke\Exception\XPubException;

enum HexVersionEnum: string
{
    case TPUB = '043587cf';
    case VPUB = '045f1cf6';
    case XPUB = '0488b21e';
    case ZPUB = '04b24746';

    /**
     * @throws XPubException
     */
    public static function fromPrefix(string $prefix): self
    {
        foreach (self::cases() as $case) {
            if ($case->name == strtoupper($prefix)) {
                return $case;
            }
        }

        throw new XPubException('invalid version');
    }
}
