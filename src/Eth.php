<?php

namespace kornrunner;

use InvalidArgumentException;

final class Eth {
    private const HASH_SIZE = 256;

    public static function hashPersonalMessage(string $message): string {
        if (stripos($message, '0x') === 0) {
            $message = substr($message, 2);
        }

        if (!ctype_xdigit($message)) {
            throw new InvalidArgumentException('Message should be a hexadecimal');
        }

        if (strlen($message) % 2) {
            throw new InvalidArgumentException('Message size cannot be odd');
        }

        $buffer = unpack('C*', (string) hex2bin($message));
        $prefix = bin2hex("\u{0019}Ethereum Signed Message:\n" . sizeof($buffer));
        return Keccak::hash(hex2bin($prefix . $message), self::HASH_SIZE);
    }

    /**
     * Recover the public key from a message hash and signature
     *
     * @param string $hash Message hash (32 bytes hex)
     * @param string $r Signature r component (32 bytes hex)
     * @param string $s Signature s component (32 bytes hex)
     * @param int $v Recovery id (0, 1, 27, or 28)
     * @return string Uncompressed public key (130 hex chars with 04 prefix)
     * @throws InvalidArgumentException
     */
    public static function ecRecover(string $hash, string $r, string $s, int $v): string {
        if ($v >= 27) {
            $v -= 27;
        }

        if ($v !== 0 && $v !== 1) {
            throw new InvalidArgumentException('Recovery id must be 0, 1, 27, or 28');
        }

        $hash = self::stripHexPrefix($hash);
        $r = self::stripHexPrefix($r);
        $s = self::stripHexPrefix($s);

        if (!ctype_xdigit($hash) || strlen($hash) !== 64) {
            throw new InvalidArgumentException('Hash must be a 32-byte hex string');
        }
        if (!ctype_xdigit($r) || strlen($r) !== 64) {
            throw new InvalidArgumentException('R must be a 32-byte hex string');
        }
        if (!ctype_xdigit($s) || strlen($s) !== 64) {
            throw new InvalidArgumentException('S must be a 32-byte hex string');
        }

        $generator = \Mdanter\Ecc\Curves\CurveFactory::getGeneratorByName(\Mdanter\Ecc\Curves\SecgCurve::NAME_SECP_256K1);
        $curve = $generator->getCurve();
        $order = $generator->getOrder();
        $adapter = new \Mdanter\Ecc\Math\ConstantTimeMath();

        $e = gmp_init($hash, 16);
        $rGmp = gmp_init($r, 16);
        $sGmp = gmp_init($s, 16);

        if (gmp_cmp($rGmp, $order) >= 0 || gmp_cmp($sGmp, $order) >= 0) {
            throw new InvalidArgumentException('Invalid signature values');
        }

        $x = $rGmp;
        if ($v & 2) {
            $x = gmp_add($x, $order);
        }

        if (gmp_cmp($x, $curve->getPrime()) >= 0) {
            throw new InvalidArgumentException('Invalid x coordinate');
        }

        $isYOdd = ($v & 1) === 1;
        $y = $curve->recoverYfromX($isYOdd, $x);
        $R = $curve->getPoint($x, $y, $order);

        if (!$generator->isValid($x, $y)) {
            throw new InvalidArgumentException('Point R is not on the curve');
        }

        $rInv = $adapter->inverseMod($rGmp, $order);
        $eNeg = gmp_mod(gmp_neg($e), $order);
        $sR = $R->mul($sGmp);
        $eG = $generator->mul($eNeg);
        $point = $sR->add($eG);
        $publicKey = $point->mul($rInv);

        $xHex = str_pad(gmp_strval($publicKey->getX(), 16), 64, '0', STR_PAD_LEFT);
        $yHex = str_pad(gmp_strval($publicKey->getY(), 16), 64, '0', STR_PAD_LEFT);

        return '04' . $xHex . $yHex;
    }

    /**
     * Verify a signature against a message hash and public key
     *
     * @param string $hash Message hash (32 bytes hex)
     * @param string $r Signature r component (32 bytes hex)
     * @param string $s Signature s component (32 bytes hex)
     * @param int $v Recovery id (0, 1, 27, or 28)
     * @param string $publicKey Public key (130 hex chars with 04 prefix)
     * @return bool
     */
    public static function ecVerify(string $hash, string $r, string $s, int $v, string $publicKey): bool {
        try {
            $recoveredPublicKey = self::ecRecover($hash, $r, $s, $v);
            return strcasecmp(self::stripHexPrefix($recoveredPublicKey), self::stripHexPrefix($publicKey)) === 0;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Sign a message using Ethereum's personal_sign format (EIP-191)
     *
     * @param string $message Plain text message
     * @param string $privateKey Private key in hex format
     * @return array ['r' => string, 's' => string, 'v' => int, 'signature' => string]
     */
    public static function signPersonalMessage(string $message, string $privateKey): array {
        $messageHash = self::hashPersonalMessage(bin2hex($message));

        $secp256k1 = new Secp256k1();
        $signature = $secp256k1->sign($messageHash, $privateKey);

        $r = str_pad(gmp_strval($signature->getR(), 16), 64, '0', STR_PAD_LEFT);
        $s = str_pad(gmp_strval($signature->getS(), 16), 64, '0', STR_PAD_LEFT);
        $v = $signature->getRecoveryParam() + 27;

        return [
            'r' => '0x' . $r,
            's' => '0x' . $s,
            'v' => $v,
            'signature' => '0x' . $r . $s . str_pad(dechex($v), 2, '0', STR_PAD_LEFT)
        ];
    }

    private static function stripHexPrefix(string $hex): string {
        if (stripos($hex, '0x') === 0) {
            return substr($hex, 2);
        }
        return $hex;
    }
}
