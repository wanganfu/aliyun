<?php

declare(strict_types=1);

namespace annon;

class SignatureV3
{
    private $ALGORITHM;
    private $AccessKeyId;
    private $AccessKeySecret;
    private $url;
    private $data;
    private $action;
    private $version = "2017-05-25";

    public function __construct(Config $config)
    {
        date_default_timezone_set('Asia/Shanghai'); // 设置时区为GMT
        $this->AccessKeyId = $config->accessId; // 从环境变量中获取RAM用户Access Key ID
        $this->AccessKeySecret = $config->accessSecret; // 从环境变量中获取RAM用户Access Key Secret
        $this->url = $config->aliServer;
        $this->ALGORITHM = 'ACS3-HMAC-SHA256'; // 设置加密算法
    }

    public function data(array $data)
    {
        $this->data = $data;
        return $this;
    }

    public function version(string $version)
    {
        $this->version = $version;
        return $this;
    }

    public function action(string $action)
    {
        $this->action = $action;
        return $this;
    }

    public function send(): mixed
    {
        // RPC接口请求
        $request = $this->createRequest(
            'POST',
            '/',
            $this->url,
            $this->action,
            $this->version
        );
        $request['queryParam'] = $this->data;
        // $this->addRequestBody($request, $this->data);

        $this->getAuthorization($request);

        return $this->callApi($request);
    }

    private function createRequest($httpMethod, $canonicalUri, $host, $xAcsAction, $xAcsVersion)
    {
        $headers = [
            'host' => $host,
            'x-acs-action' => $xAcsAction,
            'x-acs-version' => $xAcsVersion,
            'x-acs-date' => gmdate('Y-m-d\TH:i:s\Z'),
            'x-acs-signature-nonce' => bin2hex(random_bytes(16)),
        ];
        return [
            'httpMethod' => $httpMethod,
            'canonicalUri' => $canonicalUri,
            'host' => $host,
            'headers' => $headers,
            'queryParam' => [],
            'body' => null,
        ];
    }

    private function addRequestBody(&$request, $bodyData)
    {
        $request['body'] = json_encode($bodyData, JSON_UNESCAPED_UNICODE);
        $request['headers']['content-type'] = 'application/json; charset=utf-8';
    }

    private function getAuthorization(&$request)
    {
        $canonicalQueryString = $this->buildCanonicalQueryString($request['queryParam']);
        $hashedRequestPayload = hash('sha256', $request['body'] ?? '');
        $request['headers']['x-acs-content-sha256'] = $hashedRequestPayload;

        $canonicalHeaders = $this->buildCanonicalHeaders($request['headers']);
        $signedHeaders = $this->buildSignedHeaders($request['headers']);

        $canonicalRequest = implode("\n", [
            $request['httpMethod'],
            $request['canonicalUri'],
            $canonicalQueryString,
            $canonicalHeaders,
            $signedHeaders,
            $hashedRequestPayload,
        ]);

        $hashedCanonicalRequest = hash('sha256', $canonicalRequest);
        $stringToSign = $this->ALGORITHM . "\n" . $hashedCanonicalRequest;

        $signature = strtolower(bin2hex(hash_hmac('sha256', $stringToSign, $this->AccessKeySecret, true)));
        $authorization = $this->ALGORITHM . " Credential=" . $this->AccessKeyId . ",SignedHeaders=" . $signedHeaders . ",Signature=" . $signature;

        $request['headers']['Authorization'] = $authorization;
    }

    private function callApi($request)
    {
        // dd($request);
        try {
            // 通过cURL发送请求
            $url = "https://" . $request['host'] . $request['canonicalUri'];

            // 初始化cURL会话
            $ch = curl_init();

            // 根据请求类型设置cURL选项
            switch ($request['httpMethod']) {
                case "GET":
                    break;
                case "POST":
                    curl_setopt($ch, CURLOPT_POST, true);
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $request['body']);
                    break;
                case "DELETE":
                    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "DELETE");
                    break;
                case "PUT":
                    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PUT");
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $request['body']);
                    break;
                default:
                    return "Unsupported HTTP method: " . $request['body'];
            }

            // 添加请求参数到URL
            if (!empty($request['queryParam'])) {
                $url .= '?' . http_build_query($request['queryParam']);
            }

            // 设置cURL选项
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 禁用SSL证书验证，请注意，这会降低安全性，不应在生产环境中使用（不推荐！！！）
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); // 返回而不是输出内容
            curl_setopt($ch, CURLOPT_HTTPHEADER, $this->convertHeadersToArray($request['headers'])); // 添加请求头

            // 发送请求
            $result = curl_exec($ch);

            // 检查是否有错误发生
            if (curl_errno($ch)) {
                return "Failed to send request: " . curl_error($ch);
            } else {
                return json_decode($result, true);
            }

            // 关闭cURL会话
            curl_close($ch);
        } catch (\Exception $e) {
            return "Error: " . $e->getMessage();
        }
    }

    private function convertHeadersToArray($headers)
    {
        $headerArray = [];
        foreach ($headers as $key => $value) {
            $headerArray[] = $key . ': ' . $value;
        }
        return $headerArray;
    }


    private function buildCanonicalQueryString($queryParams)
    {

        ksort($queryParams);
        // Build and encode query parameters
        $params = [];
        foreach ($queryParams as $k => $v) {
            if (null === $v) {
                continue;
            }
            $str = rawurlencode($k);
            if ('' !== $v && null !== $v) {
                $str .= '=' . rawurlencode($v);
            } else {
                $str .= '=';
            }
            $params[] = $str;
        }
        return implode('&', $params);
    }

    private function buildCanonicalHeaders($headers)
    {
        // Sort headers by key and concatenate them
        uksort($headers, 'strcasecmp');
        $canonicalHeaders = '';
        foreach ($headers as $key => $value) {
            $canonicalHeaders .= strtolower($key) . ':' . trim($value) . "\n";
        }
        return $canonicalHeaders;
    }

    private function buildSignedHeaders($headers)
    {
        // Build the signed headers string
        $signedHeaders = array_keys($headers);
        sort($signedHeaders, SORT_STRING | SORT_FLAG_CASE);
        return implode(';', array_map('strtolower', $signedHeaders));
    }
}
