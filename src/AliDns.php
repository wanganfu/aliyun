<?php
declare(strict_types=1);

namespace annon;


/**
 * @property Config $config
 * Class AliDns
 * @package annon
 */
final class AliDns
{
    private $public = [
        "Format" => "JSON",
        "SignatureMethod" => "HMAC-SHA1",
        "SignatureVersion" => "1.0",
        "Version" => "2017-05-25"
    ];

    private $secret = "";
    private $aliServer = "";

    public function __construct(Config $config)
    {
        date_default_timezone_set("Asia/Shanghai");
        $this->public["SignatureNonce"] = md5(uniqid() . uniqid(md5((string)microtime(true)), true));
        $this->public["Timestamp"] = gmdate('Y-m-d\\TH:i:s\\Z');
        $this->public["AccessKeyId"] = $config->accessId;
        $this->secret = $config->accessSecret;
        $this->aliServer = $config->aliServer;
    }

    final public function version(string $version): AliDns
    {
        $this->public["Version"] = $version;
        return $this;
    }

    final public function action(string $action): AliDns
    {
        $this->public["Action"] = $action;
        return $this;
    }

    final public function data(array $data): AliDns
    {
        $this->public = array_merge($this->public, $data);
        return $this;
    }

    final public function send(): array
    {
        $params = $this->public;
        ksort($params);

        $signature = base64_encode(hash_hmac(
            'SHA1',
            'POST&%2F&' . rawurlencode(http_build_query($params)),
            $this->secret . '&',
            true
        ));

        $params['Signature'] = $signature;
        $res = $this->curl_post($params);

        return json_decode($res, true);
    }

    private function curl_post($params)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_TIMEOUT, 60);
        curl_setopt($ch, CURLOPT_URL, $this->aliServer);
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); // 返回的内容作为变量储存,而不是直接输出
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
        $res = curl_exec($ch);
        curl_close($ch);
        return $res;
    }
}