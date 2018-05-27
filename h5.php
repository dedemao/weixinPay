<?php
/**
 * H5支付
 *
 * 常见错误：
 * 1.网络环境未能通过安全验证，请稍后再试（原因：终端IP(spbill_create_ip)与用户实际调起支付时微信侧检测到的终端IP不一致）
 * 2.商家参数格式有误，请联系商家解决（原因：当前调起H5支付的referer为空）
 * 3.商家存在未配置的参数，请联系商家解决（原因：当前调起H5支付的域名与申请H5支付时提交的授权域名不一致）
 * 4.支付请求已失效，请重新发起支付（原因：有效期为5分钟，如超时请重新发起支付）
 * 5.请在微信外打开订单，进行支付（原因：H5支付不能直接在微信客户端内调起）
 */
header('Content-type:text/html; Charset=utf-8');
$mchid = 'xxxxx';          //微信支付商户号 PartnerID 通过微信支付商户资料审核后邮件发送
$appid = 'xxxxx';  //微信支付申请对应的公众号的APPID
$appKey = 'xxxxx';   //微信支付申请对应的公众号的APP Key
$apiKey = 'xxxxx';

$wxPay = new WxpayService($mchid,$appid,$apiKey);
$outTradeNo = uniqid();     //你自己的商品订单号
$payAmount = 0.01;          //付款金额，单位:元
$orderName = '支付测试';    //订单标题
$notifyUrl = 'http://www.xxx.com/wx/notify.php';     //付款成功后的回调地址(不要有问号)
$payTime = time();      //付款时间
$mwebUrl= $wxPay->createJsBizPackage($payAmount,$outTradeNo,$orderName,$notifyUrl,$payTime);
echo "<h1><a href='{$mwebUrl}'>点击跳转至支付页面</a></h1>";
exit();
class WxpayService
{
    protected $mchid;
    protected $appid;
    protected $apiKey;
    public function __construct($mchid, $appid, $key)
    {
        $this->mchid = $mchid;
        $this->appid = $appid;
        $this->apiKey = $key;
    }
    /**
     * 发起订单
     * @param float $totalFee 收款总费用 单位元
     * @param string $outTradeNo 唯一的订单号
     * @param string $orderName 订单名称
     * @param string $notifyUrl 支付结果通知url 不要有问号
     * @param string $timestamp 订单发起时间
     * @return array
     */
    public function createJsBizPackage($totalFee, $outTradeNo, $orderName, $notifyUrl, $timestamp)
    {
        $config = array(
            'mch_id' => $this->mchid,
            'appid' => $this->appid,
            'key' => $this->apiKey,
        );
        $scene_info = array(
            'h5_info' =>array(
                'type'=>'Wap',
                'wap_url'=>'1cwj.cn',
                'wap_name'=>'H5支付',
            )
        );
        $unified = array(
            'appid' => $config['appid'],
            'attach' => 'pay',             //商家数据包，原样返回，如果填写中文，请注意转换为utf-8
            'body' => $orderName,
            'mch_id' => $config['mch_id'],
            'nonce_str' => self::createNonceStr(),
            'notify_url' => $notifyUrl,
            'out_trade_no' => $outTradeNo,
            'spbill_create_ip' => $_SERVER['REMOTE_ADDR'],
            'total_fee' => intval($totalFee * 100),       //单位 转为分
            'trade_type' => 'MWEB',
            'scene_info'=>json_encode($scene_info)
        );
        $unified['sign'] = self::getSign($unified, $config['key']);
        $responseXml = self::curlPost('https://api.mch.weixin.qq.com/pay/unifiedorder', self::arrayToXml($unified));
        $unifiedOrder = simplexml_load_string($responseXml, 'SimpleXMLElement', LIBXML_NOCDATA);
        if ($unifiedOrder->return_code != 'SUCCESS') {
            die($unifiedOrder->return_msg);
        }
        if($unifiedOrder->mweb_url){
            return $unifiedOrder->mweb_url;
        }
        exit('error');
    }
    public static function curlPost($url = '', $postData = '', $options = array())
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
        $data = curl_exec($ch);
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
        return $xml;
    }
    /**
     * 获取签名
     */
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