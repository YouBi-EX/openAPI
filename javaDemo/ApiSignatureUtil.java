package ;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class ApiSignatureUtil {
    public static String accessKeyId = "accessKeyId";
    public static String signatureMethod = "signatureMethod";
    public static String signatureMethodValue = "hmacSHA256";
    public static String signatureVersion = "signatureVersion";
    public static String signatureVersionValue = "2";
    public static String timestamp = "timestamp";
    public static String signature = "signature";
    /**
     * API 签名， 签名标准： API Signature, the standard
     */

    static final DateTimeFormatter DT_FORMAT = DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss");
    static final ZoneId ZONE_GMT = ZoneId.of("Z");

    /**
     * 添加参数AccessKeyId、时间戳、SignatureVersion、SignatureMethod、Signature。
     * SignatureMethod、Signature。 Add parameter of AccessKeyId, Timestamp, SignatureVersion, SignatureMethod, Signature.
     *
     * @param accessKey AppKeyId.
     * @param secretKey AppKeySecret.
     * @param params    the original parameters， save as Key-Value ，Don't encode Value
     */
    public static Map createSignature(String accessKey, String secretKey,
                                      Map<String, String> params) {
        StringBuilder sb = new StringBuilder(1024);

        // 4.将签名按ASCII 排名
        // 4. Rank the signature according to ASCII
        params.remove(signature);
        params.put(accessKeyId, accessKey);
        params.put(signatureVersion, signatureVersionValue);
        params.put(signatureMethod, signatureMethodValue);
        params.put(timestamp, gmtNow());

        // 按照上面的顺序，将每个参数与字符“&”连接。
        // Following the sequence above, link each parameter and string with "&"
        SortedMap<String, String> map = new TreeMap<>(params);
        for (Map.Entry<String, String> entry : map.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            sb.append(key).append('=').append(urlEncode(value)).append('&');
        }
        // 删除最后的 `&`
        // Delete the last '&'
        sb.deleteCharAt(sb.length() - 1);
        // 签名:
        // Signature:
        Mac hmacSha256 = null;
        try {
            hmacSha256 = Mac.getInstance(signatureMethodValue);
            SecretKeySpec secKey = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), signatureMethodValue);
            hmacSha256.init(secKey);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("No such algorithm: " + e.getMessage());
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Invalid key: " + e.getMessage());
        }
        String payload = sb.toString();
        byte[] hash = hmacSha256.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        // 获取签名，并进行Base64编码
        // Acquire the signature and encode it with Base64 encoder
        String actualSign = Base64.getEncoder().encodeToString(hash);
        params.put(signature, actualSign);
        return params;

    }

    /**
     * @param secretKey AppKeySecret
     * @return boolean
     * @author zh
     * @date 2021/7/7 10:32
     */
    public static boolean checkSignature(String secretKey, Map<String, String> map) {
        if (!signatureVersionValue.equals(map.get(signatureVersion)) ||
                !signatureMethodValue.equals(map.get(signatureMethod))) {
            return false;
        }
        String s = map.get(signature);
        String accessKey = map.get(accessKeyId);
        String actualSign = checkCreateSignature(accessKey, secretKey, map);
        if (s.equals(actualSign)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * 添加参数AccessKeyId、时间戳、SignatureVersion、SignatureMethod、Signature。
     * SignatureMethod、Signature。 Add parameter of AccessKeyId, Timestamp, SignatureVersion, SignatureMethod, Signature.
     *
     * @param accessKey AppKeyId.
     * @param secretKey AppKeySecret.
     * @param params    the original parameters， save as Key-Value ，Don't encode Value
     */
    public static String checkCreateSignature(String accessKey, String secretKey,
                                              Map<String, String> params) {
        StringBuilder sb = new StringBuilder(1024);
        // 4.将签名按ASCII 排名
        // 4. Rank the signature according to ASCII
        params.remove(signature);

        // 按照上面的顺序，将每个参数与字符“&”连接。
        // Following the sequence above, link each parameter and string with "&"
        SortedMap<String, String> map = new TreeMap<>(params);
        for (Map.Entry<String, String> entry : map.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            sb.append(key).append('=').append(urlEncode(value)).append('&');
        }
        // 删除最后的 `&`
        // Delete the last '&'
        sb.deleteCharAt(sb.length() - 1);
        // 签名:
        // Signature:
        Mac hmacSha256 = null;
        try {
            hmacSha256 = Mac.getInstance(signatureMethodValue);
            SecretKeySpec secKey = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), signatureMethodValue);
            hmacSha256.init(secKey);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("No such algorithm: " + e.getMessage());
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Invalid key: " + e.getMessage());
        }
        String payload = sb.toString();
        byte[] hash = hmacSha256.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        // 获取签名，并进行Base64编码
        // Acquire the signature and encode it with Base64 encoder
        String actualSign = Base64.getEncoder().encodeToString(hash);
        return actualSign;

    }

    /**
     * 使用标准的URL编码
     * Encode with standard URL encoder
     *
     * @param s string
     * @return return coding result
     */
    public static String urlEncode(String s) {
        try {
            return URLEncoder.encode(s, "UTF-8").replaceAll("\\+", "%20");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException("UTF-8 encoding not supported!");
        }
    }

    /**
     * 返回秒数
     * Return epoch second
     */
    static long epochNow() {
        return Instant.now().getEpochSecond();
    }

    static String gmtNow() {
        return Instant.ofEpochSecond(epochNow()).atZone(ZONE_GMT).format(DT_FORMAT);
    }

    public static void main(String[] args) throws InterruptedException {
        Map<String, String> map = new HashMap<>();

        //查询我的挂单列表
        map.put("size", "10");
        map.put("entrustType", "0");
        map.put("direction", "0");
        map.put("secondaryCur", "USDT");
        map.put("mainCur", "ETH");
        map.put("current", "1");

        Map signatureValue = createSignature("1305819687465246721", "8e0beb8a-c5f8-4dd1-b6b6-671e1c8d197b", map);
        System.out.println(signatureValue);

    }
}
