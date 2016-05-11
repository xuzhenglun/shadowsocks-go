package shadowsocks

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"time"
)

func SetReadTimeout(c net.Conn) { //设置tcp连接超时时间
	if readTimeout != 0 {
		c.SetReadDeadline(time.Now().Add(readTimeout))
	}
}

// PipeThenClose copies data from src to dst, closes dst when done.
func PipeThenClose(src, dst net.Conn) { //未启用一次验证的时候的管道模型
	defer dst.Close()
	buf := leakyBuf.Get() //从桶里拿一个缓存
	defer leakyBuf.Put(buf)
	for { //一个管道循环，不停的从src读取，写入dst。src未加密，加密过程在ss.Write的接口实现中完成，写到dst中的已经是加密信息，并完成了包格式的构建。
		SetReadTimeout(src) //设置等待超时
		n, err := src.Read(buf)
		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			// Note: avoid overwrite err returned by Read.
			if _, err := dst.Write(buf[0:n]); err != nil {
				Debug.Println("write:", err)
				break
			}
		}
		if err != nil {
			// Always "use of closed network connection", but no easy way to
			// identify this specific error. So just leave the error along for now.
			// More info here: https://code.google.com/p/go/issues/detail?id=4373
			/*
				if bool(Debug) && err != io.EOF {
					Debug.Println("read:", err)
				}
			*/
			break
		}
	}
}

// PipeThenClose copies data from src to dst, closes dst when done, with ota verification.
func PipeThenCloseOta(src *Conn, dst net.Conn) { //启用一次验证的管道模型
	const (
		dataLenLen  = 2
		hmacSha1Len = 10
		idxData0    = dataLenLen + hmacSha1Len
	)

	defer func() {
		dst.Close()
	}()
	// sometimes it have to fill large block
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)
	for i := 1; ; i += 1 {
		SetReadTimeout(src)
		if n, err := io.ReadFull(src, buf[:dataLenLen+hmacSha1Len]); err != nil {
			if err == io.EOF {
				break
			}
			Debug.Printf("conn=%p #%v read header error n=%v: %v", src, i, n, err)
			break
		}
		dataLen := binary.BigEndian.Uint16(buf[:dataLenLen]) //解包，获取数据段长度和期望的验证值
		expectedHmacSha1 := buf[dataLenLen:idxData0]

		var dataBuf []byte
		if len(buf) < int(idxData0+dataLen) {
			dataBuf = make([]byte, dataLen)
		} else {
			dataBuf = buf[idxData0 : idxData0+dataLen]
		}
		if n, err := io.ReadFull(src, dataBuf); err != nil { //读取所有数据段，若长度不对则错误
			if err == io.EOF {
				break
			}
			Debug.Printf("conn=%p #%v read data error n=%v: %v", src, i, n, err)
			break
		}
		chunkIdBytes := make([]byte, 4)
		chunkId := src.GetAndIncrChunkId()                                        //从发送方的连接的结构提中获取当前包ID
		binary.BigEndian.PutUint32(chunkIdBytes, chunkId)                         //转换大端
		actualHmacSha1 := HmacSha1(append(src.GetIv(), chunkIdBytes...), dataBuf) //计算实际的验证值
		if !bytes.Equal(expectedHmacSha1, actualHmacSha1) {                       //不等则丢弃
			Debug.Printf("conn=%p #%v read data hmac-sha1 mismatch, iv=%v chunkId=%v src=%v dst=%v len=%v expeced=%v actual=%v", src, i, src.GetIv(), chunkId, src.RemoteAddr(), dst.RemoteAddr(), dataLen, expectedHmacSha1, actualHmacSha1)
			break
		}
		if n, err := dst.Write(dataBuf); err != nil { //验证通过，则转发
			Debug.Printf("conn=%p #%v write data error n=%v: %v", dst, i, n, err)
			break
		}
	}
}
