package shadowsocks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	OneTimeAuthMask byte = 0x10
	AddrMask        byte = 0xf
)

type Conn struct {
	net.Conn
	*Cipher
	readBuf  []byte
	writeBuf []byte
	chunkId  uint32
}

func NewConn(c net.Conn, cipher *Cipher) *Conn { //分配一个未初始化的SS连接
	return &Conn{
		Conn:     c,
		Cipher:   cipher,
		readBuf:  leakyBuf.Get(), //漏桶缓存，避免频繁的申请释放内存
		writeBuf: leakyBuf.Get()} //从桶里面拿一块缓存
}

func (c *Conn) Close() error {
	leakyBuf.Put(c.readBuf) //把缓存空间还给桶里
	leakyBuf.Put(c.writeBuf)
	return c.Conn.Close()
}

func RawAddr(addr string) (buf []byte, err error) { //从Sock5的Req里面解析出请求的地址端口信息，包装成SS的握手包
	/*
		+------+-----+-----------------------+------------------+-----------+
		| ATYP | Len |Destination Address    | Destination Port | HMAC-SHA1 |
		+------+-----+-----------------------+------------------+-----------+
		|  1   |  1  |      Variable         |         2        |  10 可选  |
		+------+-----+-----------------------+------------------+-----------+
	*/
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: address error %s %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: invalid port %s", addr)
	}

	hostLen := len(host)
	l := 1 + 1 + hostLen + 2 // addrType + lenByte + address + port
	buf = make([]byte, l)
	buf[0] = 3             // 3 means the address is domain name
	buf[1] = byte(hostLen) // host address length  followed by host address
	copy(buf[2:], host)
	binary.BigEndian.PutUint16(buf[2+hostLen:2+hostLen+2], uint16(port))
	return
}

// This is intended for use by users implementing a local socks proxy.
// rawaddr shoud contain part of the data in socks request, starting from the
// ATYP field. (Refer to rfc1928 for more information.)
func DialWithRawAddr(rawaddr []byte, server string, cipher *Cipher) (c *Conn, err error) { //与远端SS-server服务器握手并返回连接
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return
	}
	c = NewConn(conn, cipher)
	if cipher.ota {
		if c.enc == nil {
			if _, err = c.initEncrypt(); err != nil {
				return
			}
		}
		// since we have initEncrypt, we must send iv manually
		conn.Write(cipher.iv) //一次验证启用后，IV被提早生成，在发送请求前就被发送出去了，不明白为什么不和请求一起发送
		rawaddr[0] |= OneTimeAuthMask
		rawaddr = otaConnectAuth(cipher.iv, cipher.key, rawaddr) //若启用OTA，则在请求后附加10个byte长度的验证信息，并修改类型标记位
	}
	if _, err = c.write(rawaddr); err != nil { //发送请求，加密过程由ss.conn的Write和Read方法中封装。
		c.Close()
		return nil, err
	}
	return
}

// addr should be in the form of host:port
func Dial(addr, server string, cipher *Cipher) (c *Conn, err error) { //封装ss连接，实现conn接口
	ra, err := RawAddr(addr)
	if err != nil {
		return
	}
	return DialWithRawAddr(ra, server, cipher)
}

func (c *Conn) GetIv() (iv []byte) {
	iv = make([]byte, len(c.iv))
	copy(iv, c.iv)
	return
}

func (c *Conn) GetKey() (key []byte) {
	key = make([]byte, len(c.key))
	copy(key, c.key)
	return
}

func (c *Conn) IsOta() bool {
	return c.ota
}

func (c *Conn) GetAndIncrChunkId() (chunkId uint32) {
	chunkId = c.chunkId
	c.chunkId += 1
	return
}

func (c *Conn) Read(b []byte) (n int, err error) { //实现IO接口的读，解密SS连接的流量
	if c.dec == nil { //若解密表未初始化，则说明该读操作处于握手阶段，包前应该携带iv信息，读取并初始化解密表
		/*
			+-------+----------+
			|  IV   | Payload  |
			+-------+----------+
			| Fixed | Variable |
			+-------+----------+
			否则只应该有加密信息，不存在IV头
			+----------+
			| Payload  |
			+----------+
			| Variable |
			+----------+
		*/
		iv := make([]byte, c.info.ivLen)
		if _, err = io.ReadFull(c.Conn, iv); err != nil { //读取当前加密方式IV长度的数据作为IV
			return
		}
		if err = c.initDecrypt(iv); err != nil { //初始化解密表
			return
		}
		if len(c.iv) == 0 {
			c.iv = iv //保存IV到conn信息中
		}
	}

	cipherData := c.readBuf //从桶中获取一个缓存
	if len(b) > len(cipherData) {
		cipherData = make([]byte, len(b)) //缓存大小不足，只能放弃使用漏桶缓存，使用常规buff
	} else {
		cipherData = cipherData[:len(b)]
	}

	n, err = c.Conn.Read(cipherData) //读数据
	if n > 0 {
		c.decrypt(b[0:n], cipherData[0:n]) //解密后写入B以返回
	}
	return
}

func (c *Conn) Write(b []byte) (n int, err error) { //实现IO的写接口
	if c.ota { //自增包ID，用以一次验证，防止重放攻击
		chunkId := c.GetAndIncrChunkId()
		b = otaReqChunkAuth(c.iv, chunkId, b)
	}
	return c.write(b)
}

func (c *Conn) write(b []byte) (n int, err error) {
	var iv []byte
	//若c.enc已经存在，则本地变量iv不会被赋值，长度未0，iv == nil
	if c.enc == nil { //同上，加密表若不存在则生成
		iv, err = c.initEncrypt()
		if err != nil {
			return
		}
	}

	cipherData := c.writeBuf
	dataSize := len(b) + len(iv)
	if dataSize > len(cipherData) {
		cipherData = make([]byte, dataSize)
	} else {
		cipherData = cipherData[:dataSize]
	}

	//若iv == nil，则说明该写操作已经进入pipi阶段，发包前不携带有iv信息。
	if iv != nil {
		// Put initialization vector in buffer, do a single write to send both
		// iv and data.
		copy(cipherData, iv)
	}

	c.encrypt(cipherData[len(iv):], b)
	n, err = c.Conn.Write(cipherData)
	return
}
