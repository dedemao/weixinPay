<?php
header('Content-type:text/html; Charset=utf-8');
/** 请填写以下配置信息 */
$publicKeyPath = getcwd() . '/cert/public_key.pem';    //微信支付公钥证书文件路径，可以到 https://www.dedemao.com/wx/wx_publickey_download.php 生成
$apiKey = 'xxxxx';   //https://pay.weixin.qq.com 帐户中心-安全中心-API安全-APIv3密钥-设置密钥
/** 配置结束 */

$wxPay = new WxpayService($apiKey, $publicKeyPath);
$result = $wxPay->validate();
if($result===false){
    //验证签名失败
    exit('sign error');
}
$result = $wxPay->notify();
if ($result === false) {
    exit('pay error');
}
if ($result['trade_state'] == 'SUCCESS') {
    //支付成功，完成你的逻辑
    //例如连接数据库，获取付款金额$result['amount']['total']，获取订单号$result['out_trade_no']修改数据库中的订单状态等;
    //订单总金额，单位为分：$result['amount']['total']
    //用户支付金额，单位为分：$result['amount']['payer_total']
    //商户订单号：$result['out_trade_no']
    //微信支付订单号：$result['transaction_id']
    //银行类型：$result['bank_type']
    //支付完成时间：$result['success_time'] 格式为YYYY-MM-DDTHH:mm:ss+TIMEZONE
    //用户标识：$result['payer']['openid']
    //交易状态：$result['trade_state']
    //具体详细请看微信文档：https://pay.weixin.qq.com/wiki/doc/apiv3/wxpay/pay/transactions/chapter3_11.shtml
    echo 'success';
}


class WxpayService
{
    protected $apiKey;
    protected $publicKeyPath;
    protected $publicKey;

    public function __construct($apikey, $publicKeyPath)
    {
        $this->apiKey = $apikey;
        $this->publicKeyPath = $publicKeyPath;
    }

    public function getHeader($key = '')
    {
        $headers = getallheaders();
        if ($key) {
            return $headers[$key];
        }
        return $headers;
    }

    public function validate()
    {
        $serialNo = $this->getHeader('Wechatpay-Serial');
        $sign = $this->getHeader('Wechatpay-Signature');
        $timestamp = $this->getHeader('Wechatpay-Timestamp');
        $nonce = $this->getHeader('Wechatpay-Nonce');
        if (!isset($serialNo, $sign, $timestamp, $nonce)) {
            return false;
        }
//        if (!$this->checkTimestamp($timestamp)) {
//            return false;
//        }
        $body = file_get_contents('php://input');
        $message = "$timestamp\n$nonce\n$body\n";

        $certificate = openssl_x509_read(file_get_contents($this->publicKeyPath));
        $_serialNo = $this->parseSerialNo($certificate);
        if ($serialNo !== $_serialNo) return false;
        $this->publicKey = openssl_get_publickey($certificate);
        return $this->verify($message, $sign);
    }

    private function verify($message, $signature)
    {
        if (!$this->publicKey) {
            return false;
        }
        if (!in_array('sha256WithRSAEncryption', openssl_get_md_methods(true))) {
            exit("当前PHP环境不支持SHA256withRSA");
        }
        $signature = base64_decode($signature);
        return (bool)openssl_verify($message, $signature, $this->publicKey, 'sha256WithRSAEncryption');
    }

    private function parseSerialNo($certificate)
    {
        $info = openssl_x509_parse($certificate);
        if (!isset($info['serialNumber']) && !isset($info['serialNumberHex'])) {
            exit('证书格式错误');
        }

        $serialNo = '';
        if (isset($info['serialNumberHex'])) {
            $serialNo = $info['serialNumberHex'];
        } else {
            if (strtolower(substr($info['serialNumber'], 0, 2)) == '0x') { // HEX format
                $serialNo = substr($info['serialNumber'], 2);
            } else { // DEC format
                $value = $info['serialNumber'];
                $hexvalues = ['0', '1', '2', '3', '4', '5', '6', '7',
                    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'];
                while ($value != '0') {
                    $serialNo = $hexvalues[bcmod($value, '16')] . $serialNo;
                    $value = bcdiv($value, '16', 0);
                }
            }
        }

        return strtoupper($serialNo);
    }

    protected function checkTimestamp($timestamp)
    {
        return abs((int)$timestamp - time()) <= 120;
    }

    public function notify()
    {
        $postStr = file_get_contents('php://input');
        $postData = json_decode($postStr, true);
        if ($postData['resource']) {
            $data = $this->decryptToString($postData['resource']['associated_data'], $postData['resource']['nonce'], $postData['resource']['ciphertext']);
            $data = json_decode($data, true);
            return is_array($data) ? $data : false;
        }
        return false;
    }

    public function decryptToString($associatedData, $nonceStr, $ciphertext)
    {
        $ciphertext = base64_decode($ciphertext);
        if (strlen($ciphertext) <= 16) {
            return false;
        }

        // ext-sodium (default installed on >= PHP 7.2)
        if (function_exists('sodium_crypto_aead_aes256gcm_is_available') &&
            sodium_crypto_aead_aes256gcm_is_available()) {
            return sodium_crypto_aead_aes256gcm_decrypt($ciphertext, $associatedData, $nonceStr, $this->apiKey);
        }

        // ext-libsodium (need install libsodium-php 1.x via pecl)
        if (function_exists('\Sodium\crypto_aead_aes256gcm_is_available') &&
            \Sodium\crypto_aead_aes256gcm_is_available()) {
            return \Sodium\crypto_aead_aes256gcm_decrypt($ciphertext, $associatedData, $nonceStr, $this->apiKey);
        }

        // openssl (PHP >= 7.1 support AEAD)
        if (PHP_VERSION_ID >= 70100 && in_array('aes-256-gcm', openssl_get_cipher_methods())) {
            $ctext = substr($ciphertext, 0, -16);
            $authTag = substr($ciphertext, -16);

            return openssl_decrypt($ctext, 'aes-256-gcm', $this->apiKey, OPENSSL_RAW_DATA, $nonceStr,
                $authTag, $associatedData);
        }

        exit('AEAD_AES_256_GCM需要PHP 7.1以上或者安装libsodium-php');
    }
}