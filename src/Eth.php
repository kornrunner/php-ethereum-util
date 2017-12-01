<?php

namespace kornrunner;

final class Eth {
    public static function hashPersonalMessage(string $message): string {
        $buffer = unpack('C*', hex2bin($message));
        $prefix = bin2hex("\u{0019}Ethereum Signed Message:\n" . sizeof($buffer));
        return Keccak::hash(hex2bin($prefix . $message), 256);
    }
}
