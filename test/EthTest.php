<?php

namespace kornrunner;

use PHPUnit\Framework\TestCase;

class EthTest extends TestCase
{
    /**
     * @dataProvider hashPersonalMessage
     */
    public function testHashPersonalMessage($message, $expect)
    {
        $this->assertSame(Eth::hashPersonalMessage($message), $expect);
    }

    public static function hashPersonalMessage(): array {
        return [
            ['f20f20d357419f696f69e6ff05bc6566b1e6d38814ce4f489d35711e2fd2c481', '58a2db04c169254495a55b6dd5609a4902678ec29eac46df1e95994cdbeaebbb'],
            ['0xf20f20d357419f696f69e6ff05bc6566b1e6d38814ce4f489d35711e2fd2c481', '58a2db04c169254495a55b6dd5609a4902678ec29eac46df1e95994cdbeaebbb'],
            ['0xd8de0e57dc8dbe41e10a10f247f16202be05f03bfaff337dc9358c517a172e74', '988d79c9ea9404ed9ae60d3fea39c6df6c878cec5a01e05bacdd5b443e086126'],
            ['0x3e27a893dc40ef8a7f0841d96639de2f58a132be5ae466d40087a2cfa83b7179', '429217acd377a3a2c57dc2d5d12f578c5d11047b6d23f1827d6d3110b95952af'],
        ];
    }

    public function testNonHexadecimal()
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Message should be a hexadecimal');
        Eth::hashPersonalMessage(implode(range('a', 'z')));
    }

    public function testOddHex()
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Message size cannot be odd');
        Eth::hashPersonalMessage('0xabc');
    }

    /**
     * @dataProvider ecRecoverProvider
     */
    public function testEcRecover($hash, $r, $s, $v, $expectedPublicKey)
    {
        $recoveredKey = Eth::ecRecover($hash, $r, $s, $v);
        $this->assertSame(strtolower($expectedPublicKey), strtolower($recoveredKey));
    }

    public static function ecRecoverProvider(): array
    {
        return [
            // Test case 1: Known signature from secp256k1 test
            [
                '98d22cdb65bbf8a392180cd2ee892b0a971c47e7d29daf31a3286d006b9db4dc',
                'f67118680df5993e8efca4d3ecc4172ca4ac5e3e007ea774293e373864809703',
                '47427f3633371c1a30abbb2b717dbd78ef63d5b19b5a951f9d681cccdd520320',
                0,
                '04cf60398ae73fd947ffe120fba68947ec741fe696438d68a2e52caca139613ff94f220cd0d3e886f95aa226f2ad2b86be1dd5cda2813fd505d1f6a8f552904864'
            ],
            // Test case 2: Another known signature
            [
                '710aee292b0f1749aaa0cfef67111e2f716afbdb475e7f250bdb80c6655b0a66',
                '8d8bfd01c48454b5b3fed2361cbd0e8c3282d5bd2e26762e4c9dfbe1ef35f325',
                '6d6a5dc397934b5544835f34ff24263cbc00bdd516b6f0df3f29cdf6c779ccfb',
                0,
                '04cf60398ae73fd947ffe120fba68947ec741fe696438d68a2e52caca139613ff94f220cd0d3e886f95aa226f2ad2b86be1dd5cda2813fd505d1f6a8f552904864'
            ],
            // Test case 3: With v=1
            [
                '58a2db04c169254495a55b6dd5609a4902678ec29eac46df1e95994cdbeaebbb',
                '7754ba071e98e79f55b6c12db974b2c4ba565257827cf8cac0426cbf2d76ec12',
                '4bbc98ba84f2b53536c0ac8686eea9bfeb2cc768b54b3a6dd9e8166e2b892cb1',
                1,
                '04250a7ca9c072af2b582a948d90cdc3ca5bf5f32927c5aeededf5ea164e3efc0259de8b940e006c35328dc45fed83a5f32242bd22f879189e8566d5e0df408988'
            ],
            // Test case 4: With v=27 (should normalize to 0)
            [
                '98d22cdb65bbf8a392180cd2ee892b0a971c47e7d29daf31a3286d006b9db4dc',
                'f67118680df5993e8efca4d3ecc4172ca4ac5e3e007ea774293e373864809703',
                '47427f3633371c1a30abbb2b717dbd78ef63d5b19b5a951f9d681cccdd520320',
                27,
                '04cf60398ae73fd947ffe120fba68947ec741fe696438d68a2e52caca139613ff94f220cd0d3e886f95aa226f2ad2b86be1dd5cda2813fd505d1f6a8f552904864'
            ],
            // Test case 5: With 0x prefix
            [
                '0x58a2db04c169254495a55b6dd5609a4902678ec29eac46df1e95994cdbeaebbb',
                '0x6ed38b6d40fc5a7d218570427e448be3d9ca10e64c84a5fb0c14055381322e57',
                '0x13c8ac49fdacd728c55a9e093856d5f46418d6d3ccda4ad91348b5e6bd4d446d',
                0,
                '04f5cafc602335e9a9be896f8f1f866cf4c78cb594b8faae39fbab6958b84084cedf3457d9d9be65685d6e98f11c178e03b69c198626e3303b4a6b7b59a3e2b9b4'
            ],
        ];
    }

    /**
     * @dataProvider ecVerifyProvider
     */
    public function testEcVerify($hash, $r, $s, $v, $publicKey, $expected)
    {
        $result = Eth::ecVerify($hash, $r, $s, $v, $publicKey);
        $this->assertSame($expected, $result);
    }

    public static function ecVerifyProvider(): array
    {
        return [
            // Valid signature
            [
                '98d22cdb65bbf8a392180cd2ee892b0a971c47e7d29daf31a3286d006b9db4dc',
                'f67118680df5993e8efca4d3ecc4172ca4ac5e3e007ea774293e373864809703',
                '47427f3633371c1a30abbb2b717dbd78ef63d5b19b5a951f9d681cccdd520320',
                0,
                '04cf60398ae73fd947ffe120fba68947ec741fe696438d68a2e52caca139613ff94f220cd0d3e886f95aa226f2ad2b86be1dd5cda2813fd505d1f6a8f552904864',
                true
            ],
            // Valid signature with 0x prefix
            [
                '0x98d22cdb65bbf8a392180cd2ee892b0a971c47e7d29daf31a3286d006b9db4dc',
                '0xf67118680df5993e8efca4d3ecc4172ca4ac5e3e007ea774293e373864809703',
                '0x47427f3633371c1a30abbb2b717dbd78ef63d5b19b5a951f9d681cccdd520320',
                27,
                '0x04cf60398ae73fd947ffe120fba68947ec741fe696438d68a2e52caca139613ff94f220cd0d3e886f95aa226f2ad2b86be1dd5cda2813fd505d1f6a8f552904864',
                true
            ],
            // Invalid signature (wrong public key)
            [
                '98d22cdb65bbf8a392180cd2ee892b0a971c47e7d29daf31a3286d006b9db4dc',
                'f67118680df5993e8efca4d3ecc4172ca4ac5e3e007ea774293e373864809703',
                '47427f3633371c1a30abbb2b717dbd78ef63d5b19b5a951f9d681cccdd520320',
                0,
                '04250a7ca9c072af2b582a948d90cdc3ca5bf5f32927c5aeededf5ea164e3efc0259de8b940e006c35328dc45fed83a5f32242bd22f879189e8566d5e0df408988',
                false
            ],
            // Invalid signature (wrong v)
            [
                '98d22cdb65bbf8a392180cd2ee892b0a971c47e7d29daf31a3286d006b9db4dc',
                'f67118680df5993e8efca4d3ecc4172ca4ac5e3e007ea774293e373864809703',
                '47427f3633371c1a30abbb2b717dbd78ef63d5b19b5a951f9d681cccdd520320',
                1,
                '04cf60398ae73fd947ffe120fba68947ec741fe696438d68a2e52caca139613ff94f220cd0d3e886f95aa226f2ad2b86be1dd5cda2813fd505d1f6a8f552904864',
                false
            ],
        ];
    }

    public function testEcRecoverInvalidV()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Recovery id must be 0, 1, 27, or 28');
        Eth::ecRecover(
            '98d22cdb65bbf8a392180cd2ee892b0a971c47e7d29daf31a3286d006b9db4dc',
            'f67118680df5993e8efca4d3ecc4172ca4ac5e3e007ea774293e373864809703',
            '47427f3633371c1a30abbb2b717dbd78ef63d5b19b5a951f9d681cccdd520320',
            5
        );
    }

    public function testEcRecoverInvalidHash()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Hash must be a 32-byte hex string');
        Eth::ecRecover(
            '98d22cdb',
            'f67118680df5993e8efca4d3ecc4172ca4ac5e3e007ea774293e373864809703',
            '47427f3633371c1a30abbb2b717dbd78ef63d5b19b5a951f9d681cccdd520320',
            0
        );
    }

    public function testEcRecoverInvalidR()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('R must be a 32-byte hex string');
        Eth::ecRecover(
            '98d22cdb65bbf8a392180cd2ee892b0a971c47e7d29daf31a3286d006b9db4dc',
            'f671186',
            '47427f3633371c1a30abbb2b717dbd78ef63d5b19b5a951f9d681cccdd520320',
            0
        );
    }

    public function testEcRecoverInvalidS()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('S must be a 32-byte hex string');
        Eth::ecRecover(
            '98d22cdb65bbf8a392180cd2ee892b0a971c47e7d29daf31a3286d006b9db4dc',
            'f67118680df5993e8efca4d3ecc4172ca4ac5e3e007ea774293e373864809703',
            '474',
            0
        );
    }

    /**
     * @dataProvider crossLanguageTestVectors
     */
    public function testCrossLanguageCompatibility($hash, $r, $s, $v, $expectedPublicKey, $description)
    {
        $recoveredKey = Eth::ecRecover($hash, $r, $s, $v);
        $this->assertSame(strtolower($expectedPublicKey), strtolower($recoveredKey), "Failed: $description");
    }

    public static function crossLanguageTestVectors(): array
    {
        return [
            // Test from go-ethereum precompile test (ValidKey)
            // Expected address: 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b
            [
                '18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c',
                '73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f',
                'eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549',
                28,
                '043a514176466fa815ed481ffad09110a2d344f6c9b78c1d14afc351c3a51be33d8072e77939dc03ba44790779b7a1025baf3003f6732430e20cd9b76d953391b3',
                'Go-Ethereum ValidKey test'
            ],
            // Test vector: "Hello World" message
            [
                '592fa743889fc7f92ac2a37bb1f5ba1daf2a5c84741ca0e0061d243a2e6707ba',
                '7af304d2593c7a95de0c44e6dd71cef0abb33745cb489f520afbad0da45a5c15',
                '5403f6d24701fc29301dde49632be1ed551a6845ebfc77a6206c940c4cd4b90e',
                0,
                '044bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382ce28cab79ad7119ee1ad3ebcdb98a16805211530ecc6cfefa1b88e6dff99232a',
                'Hello World message'
            ],
            // Test vector: Empty message
            [
                'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
                '791fa733f5ecfb12a674cc1f72edd013b77c779614782599c394f5568a16b9f4',
                '3adabc697daa153e5151ce3f9d5cfffeebf2ad4cd0c2bd7109efe05266d4919d',
                1,
                '046a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb336b6fbcb60b5b3d4f1551ac45e5ffc4936466e7d98f6c7c0ec736539f74691a6',
                'Empty message'
            ],
            // Test vector: Long repeated message
            [
                '19e85760afdce0b93b1e6f9518359f50003c9ce57df1b846d63b20b1ca58a63c',
                '0c361191e2f0daf8596d6909a728afa7cb5fce9c8817b6afd337908bf439ed5e',
                '3806e4087411cff85121f1486ca43e988d91a928e9272326d05c9f4f4b17db6e',
                0,
                '04bb50e2d89a4ed70663d080659fe0ad4b9bc3e06c17a227433966cb59ceee020decddbf6e00192011648d13b1c00af770c0c1bb609d4d3a5c98a43772e0e18ef4',
                'Long repeated message (800 chars)'
            ],
            // Test vector: Unicode message
            [
                '8db29c0c2cc4eeb5dbdb79a697f1bad5657b033b1c904dde27b78988129d190a',
                '93107a6e332f166629f3ebf1e0e380dcc850e59f5ca322745a5b91c62f488827',
                '0df7c093ede17d2b4b7e7bf6945c6dccd8a4a0684adb0614411c32ee2b640fa7',
                0,
                '0497855f402631f09e602e5ccadc219503f07cdd4c73b2215b5418f52a7fdbfcd97c59d67b478562b62269ec23d6dfc5566bacbdc25606d4ccfd5de7cfadcf4be8',
                'Unicode message (你好世界🌍)'
            ],
        ];
    }

    /**
     * @dataProvider edgeCaseVectors
     */
    public function testEdgeCases($hash, $r, $s, $v, $expectedPublicKey, $description)
    {
        $recoveredKey = Eth::ecRecover($hash, $r, $s, $v);
        $this->assertSame(strtolower($expectedPublicKey), strtolower($recoveredKey), "Failed: $description");
    }

    public static function edgeCaseVectors(): array
    {
        return [
            // Maximum hash value (all F's)
            [
                'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                'ec48e32d5409abc6af810ec6c199c88835a2eecc42d444789af32d5e22b6b93d',
                '52d1c1f3f124c665e4d3f4160243c567558fdf746653366190a1e2d023e686c9',
                1,
                '044bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382ce28cab79ad7119ee1ad3ebcdb98a16805211530ecc6cfefa1b88e6dff99232a',
                'Maximum hash value (all F\'s)'
            ],
            // Minimum non-zero hash
            [
                '0000000000000000000000000000000000000000000000000000000000000001',
                'eb7b3c39099bc0e5f949344a120a378e5b7c3fe4bbc76cf35c0062bdcdce70bf',
                '099ba8addee976a0d9fe8b0d6724ea44741c0f3b07881d8552cfa685892e8e48',
                1,
                '04cf60398ae73fd947ffe120fba68947ec741fe696438d68a2e52caca139613ff94f220cd0d3e886f95aa226f2ad2b86be1dd5cda2813fd505d1f6a8f552904864',
                'Minimum non-zero hash'
            ],
            // Hash with leading zeros
            [
                '00000000000000000000000000000000000000000000000000000000deadbeef',
                'dcb34517a0ad00f00c0132f2cb755c2ccf7be0b1a2ad577ad324d34893c4b5a0',
                '3ff63e5ea890ff55e524321d76df9e939a80f264c9d5b9ef715c880fdf5b3668',
                1,
                '04cf60398ae73fd947ffe120fba68947ec741fe696438d68a2e52caca139613ff94f220cd0d3e886f95aa226f2ad2b86be1dd5cda2813fd505d1f6a8f552904864',
                'Hash with leading zeros (0x00...deadbeef)'
            ],
        ];
    }

    public function testEcRecoverWithAllZeroHash()
    {
        // All-zero hash should still work and return a valid public key
        $publicKey = Eth::ecRecover(
            '0000000000000000000000000000000000000000000000000000000000000000',
            'f67118680df5993e8efca4d3ecc4172ca4ac5e3e007ea774293e373864809703',
            '47427f3633371c1a30abbb2b717dbd78ef63d5b19b5a951f9d681cccdd520320',
            0
        );
        // Should return a valid 130-character hex string (04 prefix + 64 + 64)
        $this->assertSame(130, strlen($publicKey));
        $this->assertStringStartsWith('04', $publicKey);
        $this->assertTrue(ctype_xdigit($publicKey));
    }

    public function testEcVerifyWithCrossLanguageVectors()
    {
        // Test from go-ethereum (expected address: 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b)
        $isValid = Eth::ecVerify(
            '18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c',
            '73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f',
            'eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549',
            28,
            '043a514176466fa815ed481ffad09110a2d344f6c9b78c1d14afc351c3a51be33d8072e77939dc03ba44790779b7a1025baf3003f6732430e20cd9b76d953391b3'
        );
        $this->assertTrue($isValid, 'Go-Ethereum test vector should verify correctly');
    }

}
