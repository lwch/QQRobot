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

`url`: https://d.web2.qq.com/channel/login2

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

# 收取消息

在登录成功后必须不停的`POST`数据到`https://d.web2.qq.com/channel/poll2`以保持QQ号长时间在线

## POLL2

`METHOD`: POST

`url`: https://d.web2.qq.com/channel/poll2

`cookie`: [STEP5](#STEP5)中返回的cookie

`data`: r=%7B%22clientid%22%3A%2221854174%22%2C%22psessionid%22%3A%228368046764001d636f6e6e7365727665725f77656271714031302e3133392e372e31363400000ae500001a44036e0400706408946d0000000a407546514b49527756426d000000289b84f27cc12a5e70a7ebebb454add7822afd38a148e18436a491f55e1c55114757f0361344c52dd1%22%2C%22key%22%3A0%2C%22ids%22%3A%5B%5D%7D&clientid=21854174&psessionid=8368046764001d636f6e6e7365727665725f77656271714031302e3133392e372e31363400000ae500001a44036e0400706408946d0000000a407546514b49527756426d000000289b84f27cc12a5e70a7ebebb454add7822afd38a148e18436a491f55e1c55114757f0361344c52dd1

`返回`: 

    {
        "retcode": 0,
        "result": [
            {
                "poll_type": "group_message",
                "value": {
                    "msg_id": 44835,
                    "from_uin": 4179026908,
                    "to_uin": 2483577968,
                    "msg_id2": 188816,
                    "msg_type": 43,
                    "reply_ip": 176489085,
                    "group_code": 793865435,
                    "send_uin": 707424885,
                    "seq": 8462,
                    "time": 1401635969,
                    "info_seq": 298823239,
                    "content": [
                        [
                            "font",
                            {
                                "size": 10,
                                "color": "000000",
                                "style": [
                                    0,
                                    0,
                                    0
                                ],
                                "name": "宋体"
                            }
                        ],
                        "abcd "
                    ]
                }
            }
        ]
    }

`说明`:

1. `data`的格式同[STEP5](#STEP5)，其中的psessionid从[STEP5](#STEP5)的返回值中获取
2. 返回值中retcode值不同则表示不同的含义
  2.1. 0表示有[消息](#消息结构)过来了
  2.2. 102表示没有任何消息
  2.1. 116表示需要[更换ptwebqq](#ptwebqq)的值

## 消息结构

当`retcode`至为0时，返回值中含有`result`属性。其值为一个数组，其中每一个元素为一条消息。应此每次poll2返回时将拿到任意多条消息。

### 好友消息

    {
        "poll_type": "message",
        "value": {
            "msg_id": 7332,
            "from_uin": 241368154,
            "to_uin": 2483577968,
            "msg_id2": 401760,
            "msg_type": 9,
            "reply_ip": 176886367,
            "time": 1401637261,
            "content": [
                [
                    "font",
                    {
                        "size": 9,
                        "color": "0080ff",
                        "style": [
                            0,
                            0,
                            0
                        ],
                        "name": "微软雅黑"
                    }
                ],
                "aaa "
            ]
        }
    }

其中`poll_type`固定为`message`，`value`为消息的具体含义：

1. `msg_id`: 消息的id
2. `from_uin`: 好友编号（这里并不是一个QQ号，可通过这个号码查找到好友QQ号）
3. `to_uin`: 本人的QQ号
4. `msg_id2`: 消息子编号
5. `msg_type`: 消息类型
6. `reply_ip`: ip地址
7. `time`: 消息发出的时间戳
8. `content`: [消息内容](#消息内容)

### QQ群消息

    {
        "poll_type": "group_message",
        "value": {
            "msg_id": 26461,
            "from_uin": 839094401,
            "to_uin": 2483577968,
            "msg_id2": 397858,
            "msg_type": 43,
            "reply_ip": 176886371,
            "group_code": 2984018896,
            "send_uin": 3329258463,
            "seq": 54378,
            "time": 1401624424,
            "info_seq": 83905136,
            "content": [
                [
                    "font",
                    {
                        "size": 9,
                        "color": "0080ff",
                        "style": [
                            0,
                            0,
                            0
                        ],
                        "name": "微软雅黑"
                    }
                ],
                "testing "
            ]
        }
    }

其中`poll_type`固定为`group_message`，`value`为消息的具体含义：

1. `msg_id`: 消息的id
2. `from_uin`: 群编号（这里并不是一个群号，发送消息时使用）
3. `to_uin`: 本人的QQ号
4. `msg_id2`: 消息子编号
5. `msg_type`: 消息类型
6. `reply_ip`: ip地址
7. `group_code`: 群代码（可通过这个编号查找到群号）
8. `send_uin`: 发送者编号（这里并不是一个QQ号，可通过这个号码查找到其QQ号）
9. `seq`: 未知
10. `time`: 消息发出的时间戳
11. `info_seq`: 未知
12. `content`: [消息内容](#消息内容)

### 消息内容

# 发送消息

不论给好友或是QQ群发送消息均采用`POST`方式

## 给好友发送消息

`METHOD`: POST

`url`: http://d.web2.qq.com/channel/send\_buddy\_msg2

`cookie`: [POLL2](#POLL2)中获取的cookie

`data`: r=%7B%22to%22%3A241368154%2C%22face%22%3A0%2C%22msg_id%22%3A43450001%2C%22clientid%22%3A%2221854174%22%2C%22psessionid%22%3A%228368046764001d636f6e6e7365727665725f77656271714031302e3133392e372e3136340000480600001a44036e0400706408946d0000000a407546514b49527756426d0000002873b93d3e471b93ba7abb6637279c7358e5b01f9eab33a18b94a1cc3f2fd088347fff94c12b72183a%22%2C%22content%22%3A%22%5B%5C%22Hello%20World%2E%5C%22%2C%5C%22%5C%22%2C%5B%5C%22font%5C%22%2C%7B%5C%22name%5C%22%3A%5C%22%E5%AE%8B%E4%BD%93%5C%22%2C%5C%22size%5C%22%3A%5C%2210%5C%22%2C%5C%22style%5C%22%3A%5B0%2C0%2C0%5D%2C%5C%22color%5C%22%3A%5C%22000000%5C%22%7D%5D%5D%22%7D&clientid=21854174&psessionid=8368046764001d636f6e6e7365727665725f77656271714031302e3133392e372e3136340000480600001a44036e0400706408946d0000000a407546514b49527756426d0000002873b93d3e471b93ba7abb6637279c7358e5b01f9eab33a18b94a1cc3f2fd088347fff94c12b72183a

`返回`: {"retcode":0,"result":"ok"}

`说明`:

1. 返回值中retcode为0表示成功，其他值均为失败
2. `data`中r是一个json格式的数据：

        {
            "to": 241368154,
            "face": 0,
            "msg_id": 43450001,
            "clientid": "21854174",
            "psessionid": "8368046764001d636f6e6e7365727665725f77656271714031302e3133392e372e3136340000480600001a44036e0400706408946d0000000a407546514b49527756426d0000002873b93d3e471b93ba7abb6637279c7358e5b01f9eab33a18b94a1cc3f2fd088347fff94c12b72183a",
            "content": "[\"Hello World.\",\"\",[\"font\",{\"name\":\"宋体\",\"size\":\"10\",\"style\":[0,0,0],\"color\":\"000000\"}]]"
        }

  2.1. `to`: 对方uin

  2.2. `face`: 固定为0

  2.3. `msg_id`: 消息的id（单调递增）

  2.4. `clientid`: 固定值

  2.5. `psessionid`: [POLL2](#POLL2)中获取的session

  2.6. `content`: [消息内容](#消息内容字串)

3. clientid和psessionid同上

## 给QQ群发送消息

`METHOD`: POST

`url`: http://d.web2.qq.com/channel/send\_qun\_msg2

`cookie`: [POLL2](#POLL2)中获取的cookie

`data`: r=%7B%22group_uin%22%3A2659191229%2C%22msg_id%22%3A43970001%2C%22clientid%22%3A%2221854174%22%2C%22psessionid%22%3A%228368046764001d636f6e6e7365727665725f77656271714031302e3133392e372e3136340000129a00001a45036e0400706408946d0000000a40337a584351326171416d00000028ae3b3503685671887a7265c9b0ec6f33864b1b33674ba3c515301a1ef97186fb1f25e56776fb2b41%22%2C%22content%22%3A%22%5B%5C%22Hello%20World%2E%5C%22%2C%5C%22%5C%22%2C%5B%5C%22font%5C%22%2C%7B%5C%22name%5C%22%3A%5C%22%E5%AE%8B%E4%BD%93%5C%22%2C%5C%22size%5C%22%3A%5C%2210%5C%22%2C%5C%22style%5C%22%3A%5B0%2C0%2C0%5D%2C%5C%22color%5C%22%3A%5C%22000000%5C%22%7D%5D%5D%22%7D&clientid=21854174&psessionid=8368046764001d636f6e6e7365727665725f77656271714031302e3133392e372e3136340000129a00001a45036e0400706408946d0000000a40337a584351326171416d00000028ae3b3503685671887a7265c9b0ec6f33864b1b33674ba3c515301a1ef97186fb1f25e56776fb2b41

`返回`: {"retcode":0,"result":"ok"}

`说明`:

1. 返回值中retcode为0表示成功，其他值均为失败
2. `data`中r是一个json格式的数据

        {
            "group_uin": 2659191229,
            "msg_id": 43970001,
            "clientid": "21854174",
            "psessionid": "8368046764001d636f6e6e7365727665725f77656271714031302e3133392e372e3136340000129a00001a45036e0400706408946d0000000a40337a584351326171416d00000028ae3b3503685671887a7265c9b0ec6f33864b1b33674ba3c515301a1ef97186fb1f25e56776fb2b41",
            "content": "[\"Hello World.\",\"\",[\"font\",{\"name\":\"宋体\",\"size\":\"10\",\"style\":[0,0,0],\"color\":\"000000\"}]]"
        }

  2.1. `group_uin`: QQ群uin

  2.2. `msg_id`: 消息的id（单调递增）

  2.3. `clientid`: 固定值

  2.4. `psessionid`: [POLL2](#POLL2)中获取的session

  2.5. `content`: [消息内容](#消息内容字串)

3. clientid和psessionid同上

### 消息内容字串

