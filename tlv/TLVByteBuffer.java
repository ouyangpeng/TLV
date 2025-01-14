package tlv;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * TLV字节数据缓冲区
 * Created by lhd on 2015/09/26.
 */
public class TLVByteBuffer extends ByteArrayOutputStream {

    private static boolean printLog = false;

    private volatile int firstTotalSize = 0;

    private volatile int firstTagSize = 0;

    private volatile int firstLengthSize = 0;

    /**
     * 检测是否已经有第一个完整的TLV字节数据
     *
     * @return
     */
    public synchronized boolean hasNextTLVData() {
        if (count == 0) {
            return false;
        }

        compute();
        return firstTotalSize > 0 && count > 0 && firstTotalSize <= count;
    }

    @Override
    public synchronized void reset() {
        super.reset();
        firstTotalSize = 0;
        firstTagSize = 0;
        firstLengthSize = 0;
    }

    @Override
    public synchronized void close() throws IOException {
        super.close();
    }

    @Override
    public synchronized void write(byte[] buffer, int offset, int len) {
        super.write(buffer, offset, len);
    }

    /**
     * 将第一个完整的tlv字节数据截取出来并从缓存中抹除这个tlv字节数据，此方法可以正确的截取第一个完整的TLV数据包，能够解决TCP连接的粘包问题
     * 这里我是用字节数据流来实现的，其实后来看了下NIO发现也能采用ByteBuffer,并且会在一定程度上提升写数据的效率
     *
     * @return
     */
    public synchronized byte[] cutNextTLVData() {
        byte[] data = null;
        if (firstTotalSize == count) {
            data = this.toByteArray();
            reset();
        } else if (firstTotalSize < count) {
            byte[] tmp = new byte[count - firstTotalSize];
            byte[] tlvBytes = new byte[firstTotalSize];
            System.arraycopy(this.toByteArray(), firstTotalSize, tmp, 0, tmp.length);
            System.arraycopy(this.toByteArray(), 0, tlvBytes, 0, tlvBytes.length);
            reset();
            write(tmp, 0, tmp.length);
            data = tlvBytes;
        } else {
            System.err.println("firstTotalSize:" + firstTotalSize + ",count:" + count + ",firstTotalSize must smaller than count!");
        }
        return data;
    }

    private void compute() {
        if (count > 0) {
            computeTagSize();
            computeLengthSize();
            computeTotalSize();
        }
    }

    private void computeTagSize() {
        if (firstTagSize == 0) {
            firstTagSize = TLVDecoder.getTagBytesSize(this.toByteArray());
            print("firstTagSize:" + firstTagSize);
        }
    }

    private void computeLengthSize() {
        if (firstLengthSize == 0 && firstTagSize != 0) {
            firstLengthSize = TLVDecoder.getLengthBytesSize(this.toByteArray(), firstTagSize);
            print("firstLengthSize:" + firstLengthSize);
        }
    }

    private void computeTotalSize() {
        if (firstTagSize > 0 && firstLengthSize > 0 && firstTotalSize == 0) {
            byte[] lengthBytes = new byte[firstLengthSize];
            System.arraycopy(this.toByteArray(), firstTagSize, lengthBytes, 0,
                    firstLengthSize);
            int valueSize = TLVDecoder.decodeLength(lengthBytes);
            firstTotalSize = firstTagSize + firstLengthSize + valueSize;
            print("firstTotalSize:" + firstTotalSize);
        }
    }

    private void print(String log) {
        if (printLog) {
            System.out.print(log);
        }
    }
}
