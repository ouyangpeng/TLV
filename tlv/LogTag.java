package tlv;

/**
 * 包装处理日志的tag，统一加上前缀，便于日志分析
 *
 * Created by zjh on 2017/8/25.
 */

public class LogTag {


    /**
     * 增加前缀
     *
     * @param tag 实际类里面定义的tag
     * @return
     */
    public static String tag(String tag) {
        return "IM-Core-" + tag;
    }

    /**
     * 默认的tag，在不需要知道是哪个类打印的内容时使用
     *
     * @return
     */
    public static String tag() {
        return "IM-Core";
    }
}
