<?php
/**
 * 撤销订单
 * 支付交易返回失败或支付系统超时，调用该接口撤销交易。如果此订单用户支付失败，微信支付系统会将此订单关闭；如果用户支付成功，微信支付系统会将此订单资金退还给用户。
 * 注意：7天以内的交易单可调用撤销，其他正常支付的单如需实现相同功能请调用申请退款API。
 * 1.撤销订单要求必传证书，需要到https://pay.weixin.qq.com 账户中心->账户设置->API安全->下载证书
 * 2.错误码参照 ：https://pay.weixin.qq.com/wiki/doc/api/micropay.php?chapter=9_11&index=3
 */
header('Content-type:text/html; Charset=utf-8');
/* 配置开始  */
$mchid = '';          //微信支付商户号 PartnerID 通过微信支付商户资料审核后邮件发送
$appid = '';  //微信支付申请对应的公众号的APPID
$appKey = '';   //微信支付申请对应的公众号的APP Key
$apiKey = '';   //https://pay.weixin.qq.com 帐户设置-安全设置-API安全-API密钥-设置API密钥
//填写证书所在位置，证书在https://pay.weixin.qq.com 账户中心->账户设置->API安全->下载证书，下载后将apiclient_cert.pem和apiclient_key.pem上传到服务器。
$apiclient_cert = getcwd().'/cert/apiclient_cert.pem';
$apiclient_key = getcwd().'/cert/apiclient_key.pem';
$transaction_id = '';   //微信的订单号，优先使用。微信订单号与商户订单号不能同时为空
$out_trade_no = '';		//商户订单号。微信订单号与商户订单号不能同时为空
/* 配置结束 */
$wxPay = new WxpayService($mchid,$appid,$appKey,$apiKey);
$wxPay->setApiclientCert($apiclient_cert);
$wxPay->setApiclientKey($apiclient_key);
$wxPay->setTransactionId($transaction_id);
$wxPay->setOutTradeNo($out_trade_no);
$result = $wxPay->doReverse();
echo 'success';
class WxpayService
{
    protected $mchid;
    protected $appid;
    protected $appKey;
    protected $apiKey;
    protected $apiclient_cert;
    protected $apiclient_key;
    protected $transactionId;
    protected $outTradeNo;
    public $data = null;

    public function __construct($mchid, $appid, $appKey,$key)
    {
        $this->mchid = $mchid;
        $this->appid = $appid;
        $this->appKey = $appKey;
        $this->apiKey = $key;
    }

	public function setApiclientCert($apiclient_cert)
	{
		$this->apiclient_cert = $apiclient_cert;
	}

	public function setApiclientKey($apiclient_key)
	{
		$this->apiclient_key = $apiclient_key;
	}

	public function setTransactionId($transaction_id)
	{
		$this->transactionId = $transaction_id;
	}

	public function setOutTradeNo($out_trade_no)
	{
		$this->outTradeNo = $out_trade_no;
	}

    /**
     * 撤销订单
     */
    public function doReverse()
    {
        $unified = array(
            'mch_id' => $this->mchid,
            'appid' => $this->appid,
            'transaction_id' => $this->transactionId,
            'out_trade_no' => $this->outTradeNo,
            'nonce_str' => self::createNonceStr(),
        );
        $unified['sign'] = self::getSign($unified, $this->apiKey);
        $responseXml = $this->curlPost('https://api.mch.weixin.qq.com/secapi/pay/reverse', self::arrayToXml($unified));		
        $unifiedOrder = simplexml_load_string($responseXml, 'SimpleXMLElement', LIBXML_NOCDATA);
        if ($unifiedOrder === false) {
            die('parse xml error');
        }
        if ($unifiedOrder->return_code != 'SUCCESS') {
            die($unifiedOrder->return_msg);
        }
        if ($unifiedOrder->result_code != 'SUCCESS') {
            die($unifiedOrder->err_code.':'.$unifiedOrder->err_code_des);
        }
		
        return true;
    }

    public static function curlGet($url = '', $options = array())
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
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

    public function curlPost($url = '', $postData = '', $options = array())
    {
        if (is_array($postData)) {
            $postData = http_build_query($postData);
        }
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30); //设置cURL允许执行的最长秒数
        if (!empty($options)) {
            curl_setopt_array($ch, $options);
        }
        //https请求 不验证证书和host
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);

        //第一种方法，cert 与 key 分别属于两个.pem文件
        //默认格式为PEM，可以注释
        curl_setopt($ch,CURLOPT_SSLCERTTYPE,'PEM');
        curl_setopt($ch,CURLOPT_SSLCERT,$this->apiclient_cert);
        //默认格式为PEM，可以注释
        curl_setopt($ch,CURLOPT_SSLKEYTYPE,'PEM');
        curl_setopt($ch,CURLOPT_SSLKEY,$this->apiclient_key);
        //第二种方式，两个文件合成一个.pem文件
//        curl_setopt($ch,CURLOPT_SSLCERT,getcwd().'/all.pem');

        $data = curl_exec($ch);
        //var_dump($data);die;
        curl_close($ch);
        return $data;
    }

    public static function createNonceStr($length = 16)
    {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $str = '';
        for ($i = 0; $i < $length; $i++) {
            $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
        }
        return $str;
    }
    public static function arrayToXml($arr)
    {
        $xml = "<xml>";
        foreach ($arr as $key => $val) {
            if (is_numeric($val)) {
                $xml .= "<" . $key . ">" . $val . "</" . $key . ">";
            } else
                $xml .= "<" . $key . "><![CDATA[" . $val . "]]></" . $key . ">";
        }
        $xml .= "</xml>";
        file_put_contents('1.txt',$xml);
        return $xml;
    }

    public static function getSign($params, $key)
    {
        ksort($params, SORT_STRING);
        $unSignParaString = self::formatQueryParaMap($params, false);
        $signStr = strtoupper(md5($unSignParaString . "&key=" . $key));
        return $signStr;
    }
    protected static function formatQueryParaMap($paraMap, $urlEncode = false)
    {
        $buff = "";
        ksort($paraMap);
        foreach ($paraMap as $k => $v) {
            if (null != $v && "null" != $v) {
                if ($urlEncode) {
                    $v = urlencode($v);
                }
                $buff .= $k . "=" . $v . "&";
            }
        }
        $reqPar = '';
        if (strlen($buff) > 0) {
            $reqPar = substr($buff, 0, strlen($buff) - 1);
        }
        return $reqPar;
    }
}
?>