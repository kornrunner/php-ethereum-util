<?php

use kornrunner\Eth;

class EthTest extends PHPUnit\Framework\TestCase
{
    public function testHashPersonalMessage()
    {
        $this->assertSame(Eth::hashPersonalMessage('f20f20d357419f696f69e6ff05bc6566b1e6d38814ce4f489d35711e2fd2c481'), '58a2db04c169254495a55b6dd5609a4902678ec29eac46df1e95994cdbeaebbb');
    }
}