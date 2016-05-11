# shadowsocks-go 源码分析

---
# 项目结构

```
.
├── CHANGELOG
├── cmd
│   ├── shadowsocks-httpget
│   │   └── httpget.go
│   ├── shadowsocks-local
│   │   └── local.go        //ss-local主程序
│   └── shadowsocks-server
│       └── server.go       //ss-server主程序
├── config.json
├── deb                     //DEB打包配置
│   ├── DEBIAN
│   │   ├── conffiles
│   │   ├── control
│   │   ├── postinst
│   │   ├── postrm
│   │   └── prerm
│   └── etc
│       ├── init.d
│       │   └── shadowsocks
│       └── shadowsocks
│           └── config.json
├── LICENSE
├── Makefile                //利用Makefile编译安装，安装位置在$GOPATH/bin
├── README.md
├── sample-config           //配置范例
│   ├── client-multi-server.json
│   └── server-multi-port.json
├── script
│   ├── build.sh
│   ├── createdeb.sh
│   ├── curl.sh
│   ├── http.go
│   ├── README.md
│   ├── set-version.sh
│   ├── shadowsocks.exe
│   ├── test.sh
│   └── win32build.bat
├── shadowsocks             //实现了Shadowsocks包
│   ├── config.go           //配置解析
│   ├── config_test.go
│   ├── conn.go             //实现了shadowsocks.conn接口，类似net.conn
│   ├── encrypt.go          //一个封装好的加密库
│   ├── encrypt_test.go
│   ├── leakybuf.go         //一个缓存的实现，避免频繁申请释放内存
│   ├── log.go
│   ├── mergesort.go        //快排(历史遗留问题？Initial commit用到了，现在最新的代码没找到使用)
│   ├── pipe.go             //对shadowsocks.conn的一个管道封转，用于连接建立后的流量转发
│   ├── proxy.go            //封装的shadsowsock库，直接与远端ss-server建立连接
│   ├── testdata
│   │   ├── deprecated-client-multi-server.json
│   │   └── noserver.json
│   └── util.go             //工具集
└── TODO
```
> 没有实现关于UDP的支持，没有支持Tcp fast open，GoLang的官方网络库貌似还没有支持TFO

---
# 核心组件

1. shadowsocks/conn.go


    其具体的通信过程为：
    1. 调用RawAddr函数，获取目标服务器地址和端口，并将其封装为以下的格式:
    <pre>
		+------+-----+-----------------------+------------------+-----------+
		| ATYP | Len |  Destination Address  | Destination Port | HMAC-SHA1 |
		+------+-----+-----------------------+------------------+-----------+
		|  1   |  1  |      Variable         |         2        |  10 可选  |
		+------+-----+-----------------------+------------------+-----------+
    </pre>
    
    ATPY写死了为0x03，其代表了地址类型为域名
    Len是地址（域名）的长度
    随后的端口是网络序-大端写入的
    HMAC校验，当开启一次验证之后会附加在最后，占地10Byte，由IV+key为Key，对前面所有信息的摘要。

    2. DialWithRawAddr函数拿到以上的请求，ss服务器地址以及加密信息之后，向ss服务器发起tcp连接：
    首先如果OTA被启用了，会提前生成IV，并立即向ss服务器发送，随后通过shadowsocks.write完成加密Request并发往ss服务器。

    <pre>
    +-------+---------------+
    |  IV   | Encryped Data |
    +-------+---------------+
    | Fixed |    Variable   |
    +-------+---------------+
    </pre>

    如果OTA为启用，则会直接把请求用Write函数尝试发出，但是发现加密方法未初始化，则初始化IV与Chipher，并将IV附加在加密信息之后一起发出。
    看Shadowsocks文档显示应该是同时发出的，但是因为tcp是个流，貌似也可以？
    <pre>
    +-------+   +---------------+
    |  IV   |   | Encryped Data |
    +-------+   +---------------+
    | Fixed |   |    Variable   |
    +-------+   +---------------+
    </pre>

    如果一切正常，则返回连接句柄。
    此时ss-local与ss-server应该已经建立一个TCP连接，数据发送接受已经就绪。而且ss-local已经生成IV与加密方法，ss-server也已经接受到IV并完成了解密方法的初始化。
    至此，握手阶段结束，剩下的就是PIPI通信阶段。

2. shadowsocks/pipi.go

    这个文件中的函数用io包对shadowsocks.conn进行了一个封转，实现了对流量的转发。

    转发中，因为已经完成了握手，则

    1. 在OTA未启用时，即是简单的一个循环，除非转发中出现异常，否则无脑转发。
    2. 在OTA启用后，则需要对数据解包，对数据进行校验，只有通过才能被转发，否则pipe将被关闭。

    解密之后，包结构如图：第3到10字节为HMAC-SHA1验证信息，是由IV+chunkId为Key，对DATA做的HMAC摘要，本地计算后与包中的相等，则校验通过。
    <pre>
    +----------+-----------+----------+----
    | DATA.LEN | HMAC-SHA1 |   DATA   | ...
    +----------+-----------+----------+----
    |     2    |     10    | Variable | ...
    +----------+-----------+----------+----
    </pre>

3. cmd/shadowsocks-server/server.go以及cmd/shadowsocks-local/local.go
    
    这个文件为ss-server与ss-local的主程序，完成了代理服务器的作用。

    1. local.go这个程序在本地架设了一个Socks5服务器，接收来自浏览器等应用程序的请求。
    依据socks5协议，应用程序会向SOCKS5服务器发送一个握手请求，SOCKS5服务器返回正确信息则握手成功。
    随后应用程序向SOCKS5服务器发送代理请求，此时我们的local会解析这个请求，并告诉应用程序，请求已经被接收。随后解析请求，获取目标服务器的地址与端口，用之前shadowsocks.conn中的Dial函数对ss服务器发起请求，等待服务器连接建立，随后两个加密pipe建立，转发来自应用程序到目标服务器的所有流量。
    应用程序在收到SOCKS5服务器返回的请求接受回复后，开始向SOCKS5发送数据，数据经过local转发到server再转发到真实的服务器，并原路返回。

    2. server.go这个程序在墙外监听着端口，并时刻准备与local握手，建立pipe，转发数据。
    
    GO版本的Server实现了多端口不同密码，即实现了多用户不同密码不同端口。local实现了多服务器，并按照握手失败次数加权，优先连接优质服务器。

---
# 一次验证：

    每次向io接口中写入数据，或者验证的时候，都会自增一次ChunkID，ChunkID+随机的IV，保证以往的数据包不能被用以重放攻击。
