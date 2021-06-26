<?php
declare(strict_types=1);

namespace annon;


/**
 * @property string $accessId
 * @property string $accessSecret
 * @property string $aliServer
 * Class Config
 * @package annon
 */
final class Config
{
    public $accessId;
    public $accessSecret;
    public $aliServer;

    public function __construct(
        $accessId,
        $accessSecret,
        $aliServer = "https://dns.aliyuncs.com"
    )
    {
        $this->accessId = $accessId;
        $this->accessSecret = $accessSecret;
        $this->aliServer = $aliServer;
    }
}