<?php

use kornrunner\Eth;

class EthTest extends PHPUnit\Framework\TestCase
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
        ];
    }
}
