<?php
header('Content-type:text/html; Charset=utf-8');
/** 请填写以下配置信息 */
$mchid = 'xxxxx';          //微信支付商户号 PartnerID 通过微信支付商户资料审核后邮件发送
$appid = 'xxxxx';  //公众号APPID 通过微信支付商户资料审核后邮件发送
$apiKey = 'xxxxx';   //https://pay.weixin.qq.com 帐户中心-安全中心-API安全-APIv3密钥-设置密钥
$privateKeyPath = getcwd() . '/cert/apiclient_key.pem';       //apiclient_key.pem的路径，通过”微信支付商户平台证书工具“生成。https://kf.qq.com/faq/161222NneAJf161222U7fARv.html
$serialNumber = 'xxxxx'; //证书序列号 https://pay.weixin.qq.com 帐户中心-安全中心-API安全-API证书-查看证书
$outTradeNo = uniqid();     //你自己的商品订单号，最小字符长度为6
$payAmount = 0.01;          //付款金额，单位:元
$orderName = '支付测试';    //订单标题
$notifyUrl = 'https://www.xxx.com/wx/notify.php';     //付款成功后的回调地址(不要有问号)
/** 配置结束 */

$wxPay = new WxpayService($mchid, $appid, $apiKey,$privateKeyPath,$serialNumber);
$wxPay->setTotalFee($payAmount);
$wxPay->setOutTradeNo($outTradeNo);
$wxPay->setOrderName($orderName);
$wxPay->setNotifyUrl($notifyUrl);
$result = $wxPay->doPay();
if(isset($result['code'])){
    echo $result['code'].':'.$result['message'];exit();
}
//生成二维码
$url = 'https://sapi.k780.com/?app=qr.get&level=H&size=6&data=' . $result['code_url'];
echo "<img src='{$url}' style='width:300px;'><br>";
echo '二维码内容：' . $result['code_url'];

class WxpayService
{
    protected $mchid;
    protected $appid;
    protected $apiKey;
    protected $privateKeyPath;
    protected $serialNumber;
    protected $totalFee;
    protected $outTradeNo;
    protected $orderName;
    protected $notifyUrl;
    protected $auth;
    protected $gateWay='https://api.mch.weixin.qq.com/v3';

    public function __construct($mchid, $appid, $apikey, $privateKeyPath, $serialNumber)
    {
        $this->mchid = $mchid;
        $this->appid = $appid;
        $this->apiKey = $apikey;
        $this->privateKeyPath = $privateKeyPath;
        $this->serialNumber = $serialNumber;
    }

    public function setTotalFee($totalFee)
    {
        $this->totalFee = floatval($totalFee);
    }

    public function setOutTradeNo($outTradeNo)
    {
        $this->outTradeNo = $outTradeNo;
    }

    public function setOrderName($orderName)
    {
        $this->orderName = $orderName;
    }

    public function setNotifyUrl($notifyUrl)
    {
        $this->notifyUrl = $notifyUrl;
    }

    /**
     * 发起支付
     */
    public function doPay()
    {
        $reqParams = array(
            'appid' => $this->appid,        //公众号或移动应用appid
            'mchid' => $this->mchid,        //商户号
            'description' => $this->orderName,     //商品描述
            'attach' => 'pay',              //附加数据，在查询API和支付通知中原样返回，可作为自定义参数使用
            'notify_url' => $this->notifyUrl,       //通知URL必须为直接可访问的URL，不允许携带查询串。
            'out_trade_no' => $this->outTradeNo,      //商户系统内部订单号，只能是数字、大小写字母_-*且在同一个商户号下唯一，详见【商户订单号】。特殊规则：最小字符长度为6
            'amount'=>array(
                'total'=>intval($this->totalFee * 100), //订单总金额，单位为分
                'currency'=>'CNY', //CNY：人民币，境内商户号仅支持人民币
            ),
            'scene_info'=>array(        //支付场景描述
                'payer_client_ip'=>'127.0.0.1'   //调用微信支付API的机器IP
            )
        );
        $reqUrl = $this->gateWay.'/pay/transactions/native';
        $this->getAuthStr($reqUrl,$reqParams);
        $response = $this->curlPost($reqUrl,$reqParams);
        return json_decode($response,true);

    }

    public function curlPost($url = '', $postData = array(), $options = array())
    {
        if (is_array($postData)) {
            $postData = json_encode($postData);
        }
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Authorization:'.$this->auth,
            'Content-Type:application/json',
            'Accept:application/json',
            'User-Agent:'.$_SERVER['HTTP_USER_AGENT']
        ));
        curl_setopt($ch, CURLOPT_TIMEOUT, 30); //设置cURL允许执行的最长秒数
        if (!empty($options)) {
            curl_setopt_array($ch, $options);
        }
        //https请求 不验证证书和host
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        $data = curl_exec($ch);
        curl_close($ch);
        return $data;
    }

    private function getSchema()
    {
        return 'WECHATPAY2-SHA256-RSA2048';
    }

    public function getAuthStr($requestUrl,$reqParams=array())
    {
        $schema = $this->getSchema();
        $token = $this->getToken($requestUrl,$reqParams);
        $this->auth = $schema.' '.$token;
        return $this->auth;
    }

    private function getNonce()
    {
        static $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < 32; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }
        return $randomString;
    }

    public function getToken($requestUrl,$reqParams=array())
    {
        $body = $reqParams ?  json_encode($reqParams) : '';
        $nonce = $this->getNonce();
        $timestamp = time();
        $message = $this->buildMessage($nonce, $timestamp, $requestUrl,$body);
        $sign = $this->sign($message);
        $serialNo = $this->serialNumber;
        return sprintf('mchid="%s",nonce_str="%s",timestamp="%d",serial_no="%s",signature="%s"',
            $this->mchid, $nonce, $timestamp, $serialNo, $sign
        );
    }

    private function buildMessage($nonce, $timestamp, $requestUrl, $body = '')
    {
        $method = 'POST';
        $urlParts = parse_url($requestUrl);
        $canonicalUrl = ($urlParts['path'] . (!empty($urlParts['query']) ? "?{$urlParts['query']}" : ""));
        return strtoupper($method) . "\n" .
            $canonicalUrl . "\n" .
            $timestamp . "\n" .
            $nonce . "\n" .
            $body . "\n";
    }

    private function sign($message)
    {
        if (!in_array('sha256WithRSAEncryption', openssl_get_md_methods(true))) {
            throw new \RuntimeException("当前PHP环境不支持SHA256withRSA");
        }
        $res = file_get_contents($this->privateKeyPath);
        if (!openssl_sign($message, $sign, $res, 'sha256WithRSAEncryption')) {
            throw new \UnexpectedValueException("签名验证过程发生了错误");
        }
        return base64_encode($sign);
    }
}