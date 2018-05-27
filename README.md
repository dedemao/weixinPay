# weixinPay
一个PHP文件搞定微信支付系列

网上的很多PHP微信支付接入教程都颇为复杂，且需要配置和引入较多的文件，本人通过整理后给出一个单文件版的（代码只有200行左右），每个文件独立运行，不依赖和引入其他文件，希望可以给各位想接入微信支付的带来些许帮助和借鉴意义。

一个PHP文件搞定支付宝系列请移步：https://github.com/dedemao/alipay

# 在线演示
https://www.dedemao.com/wx/demo.html

# 环境依赖

PHP5.0以上，且需要开启CURL服务、SSL服务。

# 文件对应说明

native.php	  原生支付（扫码支付）

barcode.php	  刷卡支付（商户扫描用户收款码）

jsapi.php	   公众号支付

H5.php	   H5支付

redpack.php   现金红包

transfers.php 企业付款到零钱

notify.php    异步回调通知

refund.php 退款

# 注意事项

1.需要用到微信支付的哪一种支付方式，就只下载对应的单个文件即可。

2.文件开头的配置信息必须完善

3.文件需放到支付授权目录下，可以在微信支付商户平台->产品中心->开发配置中设置。

4.如提示签名错误可以通过微信支付签名验证工具进行验证：https://pay.weixin.qq.com/wiki/tools/signverify/


# 若对您有帮助，可以赞助并支持下作者哦，谢谢！

<p align="center">
    <img src="https://www.dedemao.com/uploads/zan.jpg" width="500px">
    <p align="center">联系邮箱：884358@qq.com</p>
</p>
