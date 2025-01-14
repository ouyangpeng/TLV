package tlv;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * TLV解码实现
 * <p/>
 * Created by lhd on 2015/09/26.
 */
public class TLVDecoder {

    private static boolean printLog = false;

    /**
     * 解析TLV字节数组
     *
     * @param tlvBytes
     * @return
     */
    public static TLVDecodeResult decode(byte[] tlvBytes) throws Throwable {
        TLVDecodeResult result = null;
        try {
            result = decodeImpl(tlvBytes);
        } catch (Throwable throwable) {
            throw throwable;
        }
        return result;
    }

    /**
     * 递归逐个解析TLV
     *
     * @param tlvBytes
     * @return
     */
    private static TLVDecodeResult decodeImpl(byte[] tlvBytes) throws IOException {
        if (tlvBytes == null || tlvBytes.length == 0) {
            return null;
        }
        // 截取Tag
        int tagBytesSize = getTagBytesSize(tlvBytes);
        byte[] tagBytes = new byte[tagBytesSize];
        System.arraycopy(tlvBytes, 0, tagBytes, 0, tagBytesSize);

        // 截取Length
        int lengthBytesSize = getLengthBytesSize(tlvBytes, tagBytesSize);
        byte[] lengthBytes = new byte[lengthBytesSize];
        System.arraycopy(tlvBytes, tagBytesSize, lengthBytes, 0, lengthBytesSize);

        int valueBytesSize = decodeLength(lengthBytes);
        byte[] valueBytes = new byte[valueBytesSize];
        System.arraycopy(tlvBytes, tagBytesSize + lengthBytesSize, valueBytes, 0, valueBytesSize);

        int dataType = decodeDataType(tagBytes);
        Object value = null;
        if (dataType == TLVEncoder.CONSTRUCTED_DATA) {
            int testValueBytesSize = tlvBytes.length - tagBytesSize - lengthBytesSize;
            if (testValueBytesSize != valueBytesSize) {
                // 一旦发现tlv数据体的数据长度不匹配，那么此时在tlv编解码没有问题的情况下，可能是返回来不正确的数据内容（可能是网络劫持导致的）
                System.err.println("tlv data may happen error because of data size is incorrect");
            }
            value = decodeMulti(valueBytes);
        } else {
            value = valueBytes;
        }
        TLVDecodeResult result = new TLVDecodeResult();
        result.setFrameType(decodeFrameType(tagBytes));
        result.setDataType(decodeDataType(tagBytes));
        result.setTagValue(decodeTagValue(tagBytes));
        result.setLength(decodeLength(lengthBytes));
        result.setValue(value);
        return result;
    }

    private static List<TLVDecodeResult> decodeMulti(byte[] multiTlvBytes) throws IOException {
        if (multiTlvBytes == null || multiTlvBytes.length == 0) {
            return null;
        }
        TLVByteBuffer tlvByteBuffer = new TLVByteBuffer();
        tlvByteBuffer.write(multiTlvBytes);
        List<TLVDecodeResult> list = new ArrayList<TLVDecodeResult>();
        while (tlvByteBuffer.hasNextTLVData()) {
            list.add(decodeImpl(tlvByteBuffer.cutNextTLVData()));
        }
        return list;
    }

    /**
     * 递归逐个解析TLV，此方法有一个bug，会导致tlv数据解析的数组下标越界，因此遗弃
     *
     * @return
     */
    /*@Deprecated
    private static TLVDecodeResult decodeImpl(byte[] tlvBytes, List<TLVDecodeResult> list) throws Throwable {
        if (tlvBytes == null || tlvBytes.length == 0) {
            return null;
        }
        printLog("tlvBytes length:" + tlvBytes.length);
        // 截取Tag
        int tagBytesSize = getTagBytesSize(tlvBytes);
        byte[] tagBytes = new byte[tagBytesSize];
        printLog("tagBytesSize:" + tagBytesSize);
        System.arraycopy(tlvBytes, 0, tagBytes, 0, tagBytesSize);

        // 截取Length
        int lengthBytesSize = getLengthBytesSize(tlvBytes, tagBytesSize);
        byte[] lengthBytes = new byte[lengthBytesSize];
        printLog("lengthBytesSize:" + lengthBytesSize);
        System.arraycopy(tlvBytes, tagBytesSize, lengthBytes, 0, lengthBytesSize);

        // 截取Value
        int valueBytesSize = decodeLength(lengthBytes);
        byte[] valueBytes = new byte[valueBytesSize];
        printLog("valueBytesSize:" + valueBytesSize);
        System.arraycopy(tlvBytes, tagBytesSize + lengthBytesSize, valueBytes, 0, valueBytesSize);

        // 解析数据
        TLVDecodeResult result = decodeFirstTLV(tagBytes, lengthBytes, valueBytes);
        if (result != null) {
            list.add(result);
        }

        int totalSize = tlvBytes.length;
        int firstTLVSize = tagBytesSize + lengthBytesSize + valueBytesSize;
        if (totalSize > firstTLVSize) {// 父V中有多个子TLV结构体
            decodeSecondTLV(tlvBytes, firstTLVSize, list);
        }
        return result;
    }*/

    private static void printLog(String text) {
        if (printLog) {
            System.out.print(text);
        }
    }

    /**
     * 解析同级V中的第一个TLV
     *
     * @param tagBytes
     * @param lengthBytes
     * @param valueBytes
     * @return
     */
    /*@Deprecated
    private static TLVDecodeResult decodeFirstTLV(byte[] tagBytes, byte[] lengthBytes, byte[] valueBytes) throws Throwable {
        int dataType = decodeDataType(tagBytes);
        TLVDecodeResult result = new TLVDecodeResult();
        result.setFrameType(decodeFrameType(tagBytes));
        result.setDataType(dataType);
        result.setTagValue(decodeTagValue(tagBytes));
        result.setLength(decodeLength(lengthBytes));
        if (dataType == TLVEncoder.ConstructedData) {
            printLog("TLVDecodeResult dataType:" + dataType);
            List<TLVDecodeResult> childList = new ArrayList<>();
            decodeImpl(valueBytes, childList);
            result.setValue(childList);
        } else {
            result.setValue(valueBytes);
        }

		*//*
         * if (result.getTagValue() == 0) {
		 * System.err.println("RID:"+result.getIntValue()); }
		 *//*

        return result;
    }*/

    /**
     * 解析同级V中的第二个TLV
     *
     * @param tlvBytes
     * @param firstTLVSize
     * @param list
     */
    /*@Deprecated
    private static TLVDecodeResult decodeSecondTLV(byte[] tlvBytes, int firstTLVSize, List<TLVDecodeResult> list) throws Throwable {
        int totalSize = tlvBytes.length;
        byte[] nextBytes = new byte[totalSize - firstTLVSize];
        System.arraycopy(tlvBytes, firstTLVSize, nextBytes, 0, totalSize - firstTLVSize);
        TLVDecodeResult result = decodeImpl(nextBytes, list);
        return result;
    }*/

    /**
     * 获取到全部的TLV数量
     *
     * @param tlvBytes
     * @return
     */
    public static int getTLVSize(byte[] tlvBytes) {
        int size = 0;
        // 截取Tag
        int tagBytesSize = getTagBytesSize(tlvBytes);
        byte[] tagBytes = new byte[tagBytesSize];
        System.arraycopy(tlvBytes, 0, tagBytes, 0, tagBytesSize);
        // 截取Length
        int lengthBytesSize = getLengthBytesSize(tlvBytes, tagBytesSize);
        byte[] lengthBytes = new byte[lengthBytesSize];
        System.arraycopy(tlvBytes, tagBytesSize, lengthBytes, 0,
                lengthBytesSize);
        // 截取Value
        int valueBytesSize = decodeLength(lengthBytes);
        byte[] valueBytes = new byte[valueBytesSize];
        System.arraycopy(tlvBytes, tagBytesSize + lengthBytesSize, valueBytes,
                0, valueBytesSize);
        size++;
        // 解析数据
        int dataType = decodeDataType(tagBytes);
        TLVDecodeResult result = new TLVDecodeResult();
        result.setFrameType(decodeFrameType(tagBytes));
        result.setDataType(dataType);
        result.setTagValue(decodeTagValue(tagBytes));
        result.setLength(decodeLength(lengthBytes));
        if (dataType == TLVEncoder.CONSTRUCTED_DATA) {
            size = size + getTLVSize(valueBytes);
        } else {
            // size++;
        }
        int totalSize = tlvBytes.length;
        int firstTLVSize = tagBytesSize + lengthBytesSize + valueBytesSize;
        if (totalSize > firstTLVSize) {
            byte[] nextBytes = new byte[totalSize - firstTLVSize];
            System.arraycopy(tlvBytes, firstTLVSize, nextBytes, 0, totalSize
                    - firstTLVSize);
            size = size + getTLVSize(nextBytes);
        }
        return size;
    }

    /**
     * 获取Tag占用的字节数
     *
     * @param tlvBytes
     * @return
     */
    public static int getTagBytesSize(byte[] tlvBytes) {
        int length = 0;
        for (byte b : tlvBytes) {
            length++;
            int test = b & 0x80;
            if (test == 0x00) {
                return length;
            }
        }
        return 0;
    }

    /**
     * 获取Length占用的字节数
     *
     * @param tlvBytes
     * @return
     */
    public static int getLengthBytesSize(byte[] tlvBytes, int offset) {
        int size = 0;
        for (int i = offset; i < tlvBytes.length; i++) {
            size++;
            int test = tlvBytes[i] & 0x80;
            if (test == 0x00) {
                return size;
            }
        }
        return 0;
    }

    /**
     * 解析TLV的Tag中的frameType
     *
     * @param tagBytes
     * @return
     */
    public static int decodeFrameType(byte[] tagBytes) {
        return TLVEncoder.PRIVATE_FRAME & tagBytes[0];
    }

    /**
     * 解析TLV的Tag中的dataType
     *
     * @param tagBytes
     * @return
     */
    public static int decodeDataType(byte[] tagBytes) {
        return TLVEncoder.CONSTRUCTED_DATA & tagBytes[0];
    }

    /**
     * 解析TLV的Tag中的tagValue
     *
     * @param tagBytes
     * @return
     */
    public static int decodeTagValue(byte[] tagBytes) {
        int tagValue = 0x80 & tagBytes[0];
        int result = 0;
        if (tagValue != 0x80) {
            result = tagBytes[0] & 0x1f;
        } else {
            //高位到低位解析
//			result = decodeTagValueFromHighToLowBit(tagBytes);
            //低位到高位解析
            result = decodeValueFromLowToHighBit(tagBytes);
        }
        return result;
    }

    /**
     * 从高位到低位解析tagValue
     *
     * @param bytes
     * @return
     */
    private static int decodeValueFromHighToLowBit(byte[] bytes) {
        int result = 0;
        for (int i = 1; i < bytes.length; i++) {
            result |= (0x7f & bytes[i]) << 7 * (bytes.length - i - 1);
        }
        return result;
    }

    /**
     * 从低位到高位解析tagValue
     *
     * @param bytes
     * @return
     */
    private static int decodeValueFromLowToHighBit(byte[] bytes) {
        int result = 0;
        for (int i = 1; i < bytes.length; i++) {
            result |= (0x7f & bytes[i]) << 7 * (i - 1);
        }
        return result;
    }

    /**
     * 解析TLV中的Length
     *
     * @param lengthBytes
     * @return
     */
    public static int decodeLength(byte[] lengthBytes) {
        int result = 0;
        int len = 0x80 & lengthBytes[0];
        if (len != 0x80) {
            result = (int) TLVUtils.byteArrayToLong(lengthBytes);
        } else {
            result |= 0x7f & lengthBytes[0];
            for (int i = 1; i < lengthBytes.length; i++) {
//                result |= (0x7f & lengthBytes[i]) << 7 * (lengthBytes.length - i);
                result |= (0x7f & lengthBytes[i]) << 7 * i;
            }
        }
        return result;
    }
}
