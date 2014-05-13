# 登录

## STEP1

检查是否需要输入验证码

`METHOD`: GET

`url`: https://ssl.ptlogin2.qq.com/check?uin=QQ号&appid=1003903&r=0.14233942252344134

`cookie`: 无

`返回`: ptui_checkVC('0','!W61','\x00\x00\x00\x00\x9b\x8f\xdb\xab');

`说明`:

1. 若返回值中第一个参数为1则说明需要输入验证码
2. 第二个参数为verifycode
3. 第三个参数为bits

## STEP2(可选)

获取验证码

`METHOD`: GET

`url`: https://ssl.captcha.qq.com/getimage?aid=1003903&r=0.577911190026398&uin=QQ号

`cookie`: 无

`返回`: 验证码内容，jpeg格式

## STEP3

首次登录

`METHOD`: GET

`url`: https://ssl.ptlogin2.qq.com/login?u=QQ号&p=密码&verifycode=验证码&webqq_type=10&remember_uin=1&login2qq=1&aid=1003903&u1=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html%3Flogin2qq%3D1%26webqq_type%3D10&h=1&ptredirect=0&ptlang=2052&daid=164&from_ui=1&pttype=1&dumy=&fp=loginerroralert&action=6-53-32873&mibao_css=m_webqq&t=4&g=1&js_type=0&js_ver=10077&login_sig=qBpuWCs9dlR9awKKmzdRhV8TZ8MfupdXF6zyHmnGUaEzun0bobwOhMh6m7FQjvWA"

`cookie`: [STEP1](#STEP1)或[STEP2](#STEP2)中返回的cookie

`返回`: ptuiCB('0','0','http://ptlogin4.web2.qq.com/check_sig?pttype=1&uin=2483577968&service=login&nodirect=0&ptsig=S9TKn7pHCS74-LPNRS0RG77hl-emz6spL6ijhJQiMjQ_&s_url=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html%3Flogin2qq%3D1%26webqq_type%3D10&f_url=&ptlang=2052&ptredirect=100&aid=1003903&daid=164&j_later=0&low_login_hour=0&regmaster=0&pt_login_type=1&pt_aid=0&pt_aaid=0&pt_light=0','0','登录成功！', 'QQ机器人');

`说明`:

1. 密码的加密算法为md5\_str(md5\_str(md5\_hex(password) + bits) + verifycode),其中md5\_str返回的是md5运算后字符串的结果，其中的字母均为大写
2. 返回值中第3个参数是一个回调地址，将在[STEP4](#STEP4)中用到
3. 返回值中第5个参数为登录是否成功的状态
4. 返回值中第6个参数为当前账号的昵称
5. 其他参数均`无用`

## STEP4

回调login返回的url

`METHOD`: GET

`url`: [STEP3](#STEP3)中返回的url

`cookie`: 无

`返回`: 

    <!DOCTYPE html>
    <html>
    <head>
	    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	    <title>登录成功，跳转中...</title>
    </head>
    <body>
	    <div>登录成功，跳转中...</div>
	    <script>
		    document.domain="qq.com";
		    parent.alloy.portal.validatePTLoginSuccess({
			    url:document.location.href
		    });
	    </script>
    </body>
    </html>

## STEP5

第二次登录

`METHOD`: POST

`url`: http://d.web2.qq.com/channel/login2

`cookie`: [STEP4](#STEP4)中返回的cookie

`data`: r=%7B%22status%22%3A%22online%22%2C%22ptwebqq%22%3A%22d85409b0de7a06ac08a3db66184217efb8dd387bf44d145e6d6a4e8cf3dda169%22%2C%22passwd%5Fsig%22%3A%22%22%2C%22clientid%22%3A%2221854174%22%2C%22psessionid%22%3Anull%7D%22clientid=21854174%22psessionid=null

`返回`: 

    {
        "retcode": 0,
        "result": {
            "uin": 2483577968,
            "cip": 1033433032,
            "index": 1075,
            "port": 56611,
            "status": "online",
            "vfwebqq": "4eeffd9c04080fa34147e230e9031a656feeba109078243488d7d3100fc43b8ff45606d54576ae41",
            "psessionid": "8368046764001d636f6e6e7365727665725f77656271714031302e3133392e372e313634000039cb000015fc036e0400706408946d0000000a406842386251773255786d000000284eeffd9c04080fa34147e230e9031a656feeba109078243488d7d3100fc43b8ff45606d54576ae41",
            "user_state": 0,
            "f": 0
        }
    }

`说明`:

1. `data`中的r值为一个json格式的值
2. 其中的`online`属性表示当前状态，有在线、离线、隐身等
3. 其中`ptwebqq`为[STEP3](#STEP3)中返回的cookie里所带的`ptwebqq`值
4. 其中`clientid`可为任意值
5. 其中`psessionid`固定为null
5. `data`中`clientid`和`psessionid`与上面的值相同
6. 返回值同样是一个json数据，其中`retcode`值为0时表示登录成功，其他值均失败

