<?php
declare(strict_types=1);

require_once __DIR__ . "/../vendor/autoload.php";

use annon\AliDns;
use annon\Config;

$secret = "you secret";
$key = "you secert id";

$aliDns = (new AliDns(new Config($key, $secret)));

$res = $aliDns->data([
        "DomainName" => "avza.cn",
        "Type" => "TXT"
    ])
    ->action("DescribeDomainRecords")
    ->send();
var_dump($res);

$res = $aliDns->data([
        "RecordId" => "xxxxxxxxxxxxxxxxxx"
    ])
    ->action("DescribeDomainRecordInfo")
    ->send();
var_dump($res);

$res = $aliDns->data([
        "DomainName" => "avza.cn"
    ])
    ->action("DescribeDomainRecordInfo")
    ->send();
var_dump($res);
