package tlv;

/**
 * TLV编码实现
 * <p/>
 * Created by lhd on 2015/09/26.
 *
 * <p><a href="https://my.oschina.net/maxid/blog/206546">看懂通信协议：自定义通信协议设计之TLV编码应用</a>
 * <p><img src= "https://ahq02g.dm2303.livefilestore.com/y2pE8maaJOVi2hTlZv13O7S6LxqLsbTzFf7HCG-J-Rnxhg2UWvmKHMTT2tvFMs3zjJGEb7WIdgQE3d8Wu6HroKynVJG2n1j_yFr4ckHlad1-7w/TLV_DISC.png?psid=1">
 * <p>
 * 第6~7位：表示TLV的类型，00表示TLV描述的是基本数据类型(Primitive Frame, int,string,long...)，01表示用户自定义类型(Private Frame，常用于描述协议中的消息)。
 * 第5位：表示Value的编码方式，分别支持Primitive及Constructed两种编码方式, Primitive指以原始数据类型进行编码，Constructed指以TLV方式进行编码，0表示以Primitive方式编码，1表示以Constructed方式编码。
 * 第0~4位：当Tag Value小于0x1F(31)时，首字节0～4位用来描述Tag Value，否则0~4位全部置1，作为存在后续字节的标志，Tag Value将采用后续字节进行描述。
 */
public class TLVEncoder {

    /**
     * 基本数据类型             第6~7位：表示TLV的类型，00表示TLV描述的是基本数据类型(Primitive Frame)，即 十六进制的0x00，十进制为0
     */
    public static final int PRIMITIVE_FRAME = 0x00;

    /**
     * 私有类型                第6~7位：表示TLV的类型，01表示用户自定义类型(Private Frame，常用于描述协议中的消息)，即 十六进制的0x40，十进制为64
     */
    public static final int PRIVATE_FRAME = 0x40;

    /**
     * 基本类型数据编码
     * <p>
     * 第5位：表示Value的编码方式，分别支持Primitive及Constructed两种编码方式,
     * Primitive指以原始数据类型进行编码，Constructed指以TLV方式进行编码，0表示以Primitive方式编码，1表示以Constructed方式编码。
     * <p>
     * 即 十六进制的0x00，十进制为0
     *
     * <p>
     * <br/>Primitive Data 编码
     * <br/><img src= "https://ahq02g.dm2303.livefilestore.com/y2pr4FIH8dqYIpQvawEBEajtRXuWPFHRb9zS3EeMttlyi_TJjWTIQgg9MQw2v_qVr740-w6kcn_e6RseACqeUlIeYXiTozKo6lT-1HYuv6rdYY/P-DATA.png?psid=1">
     */
    public static final int PRIMITIVE_DATA = 0x00;

    /**
     * TLV类型数据编码
     * <p>
     * 第5位：表示Value的编码方式，分别支持Primitive及Constructed两种编码方式,
     * Primitive指以原始数据类型进行编码，Constructed指以TLV方式进行编码，0表示以Primitive方式编码，1表示以Constructed方式编码。
     * <p>
     * 即 十六进制的0x20，十进制为32
     *
     * <p>
     * <br/>Constructed Data 编码
     * <br/><img src= "https://ahq02g.dm2304.livefilestore.com/y2pafCW8TjTzhOrF86tdHK7Qrfl_01j4lZFrKYObH_Y1ACBcMmo1dat9Eohp30bJKLuDVxo_Y_nwN1wy93gddHzgVh_SbJcXTQD48At8DE2SQI/C-DATA.png?psid=1">
     */
    public static final int CONSTRUCTED_DATA = 0x20;

    /**
     * TLV格式编码
     *
     * @param frameType TLV类型，Tag首字节最左两bit为00：基本类型，01：私有类型(自定义类型)
     * @param dataType  数据类型，Tag首字节第5位为0：基本数据类型，1：结构类型(TLV类型，即TLV的V为一个TLV结构)
     * @param tagValue  Tag 值，即协议中定义的交易类型 或 基本数据类型
     * @param value     TLV类型的值
     * @return TLV格式编码后的内容
     */
    public static TLVEncodeResult encode(int frameType, int dataType,
                                         int tagValue, byte[] value) {
        /*TLVEncodeResult tlvEncodeResult = TLVCache.getTLVEncodeResult(frameType, dataType, tagValue, value);
        if (tlvEncodeResult != null) {
            return tlvEncodeResult;
        }*/

        byte[] tagBytes = encodeTag(frameType, dataType, tagValue);
        // System.out.println("tag:"+new BigInteger(1, tagBytes).toString(2));

        byte[] lengthBytes = encodeLength(value == null ? 0 : value.length);
//		System.out.println("length:" + value.length);
//		System.out.println("lengthBytes:" + new BigInteger(1, lengthBytes).toString(2));

        TLVEncodeResult result = new TLVEncodeResult();
        result.setTagBytes(tagBytes);
        result.setTagSize(tagBytes.length);
        result.setLengthBytes(lengthBytes);
        result.setLengthSize(lengthBytes.length);
        result.setValueBytes(value);
        result.setValueSize(value == null ? 0 : value.length);
//        TLVCache.addTlvEncoderCache(frameType, dataType, tagValue, value, result);
        return result;
    }

    /**
     * TLV格式编码
     *
     * @param frameType TLV类型，Tag首字节最左两bit为00：基本类型，01：私有类型(自定义类型)
     * @param dataType  数据类型，Tag首字节第5位为0：基本数据类型，1：结构类型(TLV类型，即TLV的V为一个TLV结构)
     * @param tagValue  Tag 值，即协议中定义的交易类型 或 基本数据类型
     * @param value     TLV类型的值
     * @return TLV格式编码后的内容
     */
    public static TLVEncodeResult encode(int frameType, int dataType,
                                         int tagValue, String value) {
        if (value != null)
            return encode(frameType, dataType, tagValue, value.getBytes());
        else
            return encode(frameType, dataType, tagValue, (byte[]) null);
    }

    /**
     * TLV格式编码
     *
     * @param frameType TLV类型，Tag首字节最左两bit为00：基本类型，01：私有类型(自定义类型)
     * @param dataType  数据类型，Tag首字节第5位为0：基本数据类型，1：结构类型(TLV类型，即TLV的V为一个TLV结构)
     * @param tagValue  Tag 值，即协议中定义的交易类型 或 基本数据类型
     * @param value     TLV类型的值
     * @return TLV格式编码后的内容
     */
    public static TLVEncodeResult encode(int frameType, int dataType,
                                         int tagValue, long value) {
        return encode(frameType, dataType, tagValue,
                TLVUtils.longToByteArray(value));
    }

    /**
     * <p>
     * 生成 Tag ByteArray
     * </p>
     * <p>
     * <b>其中 tagValue <= 2097151，超过之后编码的结果是错误的</b>
     * </p>
     * <p>
     * Tag首节字说明
     * <br/>
     * <br/>第6~7位：表示TLV的类型，00表示TLV描述的是基本数据类型(Primitive Frame, int,string,long...)，01表示用户自定义类型(Private Frame，常用于描述协议中的消息)。
     * <br/>第5位：表示Value的编码方式，分别支持Primitive及Constructed两种编码方式, Primitive指以原始数据类型进行编码，Constructed指以TLV方式进行编码，0表示以Primitive方式编码，1表示以Constructed方式编码。
     * <br/>第0~4位：当Tag Value小于0x1F(31)时，首字节0～4位用来描述Tag Value，否则0~4位全部置1，作为存在后续字节的标志，Tag Value将采用后续字节进行描述。
     * <br/><img src= "https://ahq02g.dm2302.livefilestore.com/y2ps4GDdL09TgISfrKPQk3Y3px1l-EH0YhcDg7tPR5Nme7OAKXRYZDUKqXGL7gYD8nnN8DG2qwNIJDOICKsL3szoZzGYNsT-V4lTpdfX2t1_vY/TAG_FB.png?psid=1">
     * </p>
     * <p><br/><br/>Tag后续字节说明<br/>
     * 后续字节采用每个字节的0～6位（即7bit）来存储Tag Value, 第7位用来标识是否还有后续字节。
     * <br/>第7位：描述是否还有后续字节，1表示有后续字节，0表示没有后续字节，即结束字节。
     * <br/>第0~6位：填充Tag Value的对应bit(从低位到高位开始填充)，如：Tag Value为：0000001 11111111 11111111 (10进制：131071), 填充后实际字节内容为：10000111 11111111 01111111。
     * <img src= "https://ahq02g.dm1.livefilestore.com/y2p0tGpzvc24_EpddfBEZsdEqUBHaRIMFSom4izyJN4ryrf2boD7g4FfqyVtiSqmd5UOc9TuNxHwmsCmkm2JFD8hL-HlOYIcixa6BMgc9_RbgY/TAG_NB.png?psid=1">
     * </p>
     * @param frameType TLV类型，Tag首字节最左两bit为00：基本类型，01：私有类型(自定义类型)
     * @param dataType  数据类型，Tag首字节第5位为0：基本数据类型，1：结构类型(TLV类型，即TLV的V为一个TLV结构)
     * @param tagValue  Tag 值，即协议中定义的交易类型 或 基本数据类型
     * @return Tag ByteArray
     */
    public static byte[] encodeTag(int frameType, int dataType, int tagValue) {
        int result = frameType | dataType | tagValue;
        int digit = 0;
        // 0x1f 为 31 ，二进制为11111
        if (tagValue < 0x1f){
            // 1 byte tag
            result = frameType | dataType | tagValue;
        } else{
            // mutli byte tag
            result = frameType | dataType | 0x80;   // 0x80 为 128，二进制为10000000
            digit = (int) computeTagDigit(tagValue);
            result <<= 8 * digit;
            //高位到低位
//			rawTag = encodeTagValueFromHighToLowBit(rawTag, digit, tagValue);
            //低位到高位
            result = encodeValueFromLowToHighBit(result, digit, tagValue);
        }
        return intToByteArrayForTag(result, digit);
    }

    /**
     * 从高位到低位对tagValue进行编码
     *
     * @param result
     * @param digit
     * @param value
     * @return
     */
    private static int encodeValueFromHighToLowBit(int result, int digit, int value) {
        //高位到低位
        for (int i = digit - 1; i > 0; i--) {
            result |= ((value >> i * 7 & 0x7f) | 0x80) << i * 8;
        }
        result |= value & 0x7f;
        return result;
    }

    /**
     * 从低位到高位对tagValue进行编码
     *
     * @param result 形参，int类型的只传值进来，因此必须反馈编码结果
     * @param digit
     * @param value
     * @return
     */
    private static int encodeValueFromLowToHighBit(int result, int digit, int value) {
        //低位到高位
        for (int i = 0; i < digit - 1; i++) {
            // 十六进制的0x7f， 十进制为 127， 二进制为  1111111
            // 十六进制的0x80， 十进制为 128， 二进制为  10000000
            result |= ((value >> i * 7 & 0x7f) | 0x80) << (digit - 1 - i) * 8;
//			System.out.println("tag:"+Integer.toBinaryString(((tagValue >> i * 7 & 0x7f) | 0x80) << (digit - 1 - i) * 8));
//			System.out.println("rawTag:" + Integer.toBinaryString(rawTag));
        }
//		System.out.println("high:" + Integer.toBinaryString((tagValue >> (digit - 1) * 7) & 0x7f));
        result |= (value >> (digit - 1) * 7) & 0x7f;
        return result;
    }

    private static byte[] intToByteArrayForTag(int value, int digit) {
        byte[] result = new byte[digit + 1];
        int length = result.length;
        result[0] = (byte) ((value >> (8 * digit)) & 0xff);
        for (int i = 0; i < length; i++) {
            //这里有两种方法来实现高位到低位或者低位到高位的编码，具体选择哪种待评估
//			if (i == length -1) {
//				result[i] = (byte) ((value >> (8 * (i - 1))) & 0x7f);
//			} else {
//				result[i] = (byte) ((value >> (8 * (i - 1))) & 0xff | 0x80);
//			}
            result[i] = (byte) ((value >> (8 * (digit - i))) & 0xff);//高位到低位
        }
        return result;
    }

    private static byte[] intToByteArrayForLength(int value, int digit) {
        byte[] result = new byte[digit];
        int length = result.length;
        // 0xff  对应的十进制为255    对应的二进制为： 11111111
        result[0] = (byte) ((value >> (8 * (digit - 1))) & 0xff);
        for (int i = 1; i < length; i++) {
            //这里有两种方法来实现高位到低位或者低位到高位的编码，具体选择哪种待评估
//			if (i == length -1) {
//				result[i] = (byte) ((value >> (8 * (i - 1))) & 0x7f);
//			} else {
//				result[i] = (byte) ((value >> (8 * (i - 1))) & 0xff | 0x80);
//			}
            result[i] = (byte) ((value >> (8 * (digit - i - 1))) & 0xff);//高位到低位
        }
        return result;
    }

    /**
     * 对数计算换底公式
     *
     * @param value
     * @param base
     * @return
     */
    public static double log(double value, double base) {
        return Math.log(value) / Math.log(base);
    }

    /**
     * 计算Tag字节数,推导出来的计算公式
     *
     * @param value
     * @return
     */
    private static double computeTagDigit(double value) {
        if (value < 0x1f) {
            throw new IllegalArgumentException(
                    "the tag value must not less than 31.");
        }
        return Math.ceil(log(value + 1, 128));
    }

    /**
     * 生成Length的byte数组
     *
     * <p>
     *     描述Value部分所占字节的个数，编码格式分两类：定长方式（DefiniteForm）和不定长方式（IndefiniteForm），其中定长方式又包括短形式与长形式。
     *     <br/>1、 定长方式
     *       <br/>定长方式中，按长度是否超过一个八位，又分为短、长两种形式，编码方式如下：
     *             <br/>1)短形式： 字节第7位为0，表示Length使用1个字节即可满足Value类型长度的描述，范围在0~127之间的。
     *             <br/><img src = "https://ahq02g.dm2303.livefilestore.com/y2pTUflngsP_OT4c4ReAdXLsOjD88bI2HcMc1nKHN6bouH9UDCYdGhKk33-EVJ-66Ms2zFv56R724HjvFb1OwB1_DBt1HxA40dtO6qKAfzTpJI/LENGTH-S.png?psid=1"/>
     *             <br/>2)长形式： 即Value类型的长度大于127时，Length需要多个字节来描述，这时第一个字节的第7位置为1，0~6位用来描述Length值占用的字节数，然后直将Length值转为byte后附在其后，如： Value大小占234个字节（11101010）,由于大于127，这时Length需要使用两个字节来描述，10000001 11101010
     *              <br/><img src = "https://ahq02g.dm2302.livefilestore.com/y2pPaMKjeIKEYAljAyvYv2qXf-zukGgyLXdqTgHVOp3e-J7PyObfa_uLeTJPHa7Ny5gPMEeE-LB-_AnOE1YVIC_gA08rP8vfh17yQuw7ngjow8/LENGTH-L.png?psid=1"/>
     *
     *
     *      <br/> 2、不定长方式
     *      <br/> Length所在八位组固定编码为0x80，但在Value编码结束后以两个0x00结尾。这种方式使得可以在编码没有完全结束的情况下，可以先发送部分数据给对方。
     *      <br/><img src = "https://ahq02g.dm2301.livefilestore.com/y2p8bAu4O1EEq4cCoORp0uogPl7-CCyC2k31Rdimj1MyNQHVFp47GgO-0oJdsMhshg8zZND53TsNP6lcigss-FvdC8OD_zu4icx49H5NyCzU8w/LENGHT-D.png?psid=1"/>
     * </p>
     * @param length
     * @return
     */
    public static byte[] encodeLength(int length) {
        if (length < 0) {
            throw new IllegalArgumentException(
                    "the length must not less than 0.");
        }
        // 短形式
        if (length < 128) {
            byte[] lengthBytes = new byte[1];
            lengthBytes[0] = (byte) (0x7f & length);
            return lengthBytes;
        } else { // 长形式
            int digit = (int) computeLengthDigit(length);
            int result = 0;
            result = encodeValueFromLowToHighBit(result, digit, length);
            return intToByteArrayForLength(result, digit);
        }
    }

    /**
     * 计算length的字节数,推导出来的计算公式
     *
     * @param length
     * @return
     */
    private static double computeLengthDigit(int length) {
        return Math.ceil(log(length + 1, 128));
    }
}
