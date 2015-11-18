package jdk;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.codehaus.jackson.*;

@Component
public class RongCloudClient {
    // 获取token的url
    private static String AUTH_URL = "https://api.cn.rong.io/user/getToken.json";
    // 发送二人会话的url
    // private static String PUBLISH_URL = "https://api.cn.rong.io/message/publish.json";

    // 发送系统消息(新接口)
    private static String SYSTEM_PUBLISH_URL = "https://api.cn.rong.io/message/system/publish.json";


    // 发送应用广播(发送消息给一个应用下的所有注册用户)的url
    private static String BROADCAST_URL = "https://api.cn.rong.io/message/broadcast.json";

    // 创建聊天室URL
    private static String CREATE_CHATROOM_URL = "https://api.cn.rong.io/chatroom/create.json";
    // 销毁聊天室URL
    private static String DESTROY_CHATROOM_URL = "https://api.cn.rong.io/chatroom/destroy.json";

    private static final Logger logger = LoggerFactory.getLogger(RongCloudClient.class);

    @Value("${cn.ohface.server.rcloud.appKey}")
    private String appKey;

    @Value("${cn.ohface.server.rcloud.appSecret}")
    private String appSecret;

    @Value("${cn.ohface.server.rcloud.userId}")
    private long serverUserId;

    @Autowired
    private SecureRandom random;

    @Autowired
    private ObjectMapper objectMapper;


    /**
     * 通过用户id获取融云token
     * 
     * @param userId 用户id
     * @return 该用户对应的融云token
     * @throws RongAuthException
     */
    public String getRcloudToken(long userId)  {
        String result = null;
        HttpClient httpclient = wrapClient(new DefaultHttpClient());

        HttpPost httppost = new HttpPost(AUTH_URL);

        dealRequestHeader(httppost, appKey, appSecret);

        try {
            List<NameValuePair> nvps = new ArrayList<NameValuePair>();
            nvps.add(new BasicNameValuePair("userId", String.valueOf(userId)));
            nvps.add(new BasicNameValuePair("name", ""));
            nvps.add(new BasicNameValuePair("portraitUri", ""));

            httppost.setEntity(new UrlEncodedFormEntity(nvps, "UTF-8"));
            HttpResponse response = httpclient.execute(httppost);
            HttpEntity entity = response.getEntity();
            String strResultJson = EntityUtils.toString(entity);
            int statCode = response.getStatusLine().getStatusCode();
            if (statCode != 200) {
                throw new RongAuthException(statCode, result, null);
            } else {
                @SuppressWarnings("rawtypes")
                Map mapResultJson = objectMapper.readValue(strResultJson, Map.class);
                logger.info("getRcloudToken(userId=[{}]) return:[{}]", new Object[] {userId, strResultJson});
                int code = (int) mapResultJson.get("code");
                if (code == 200) {
                    result = mapResultJson.get("token").toString();
                } else {
                    throw new RongAuthException(code, strResultJson, null);
                }
            }

        } catch (Exception ex) {
            if (ex instanceof RongAuthException) {
                throw (RongAuthException) ex;
            } else {
                throw new RongAuthException(502, ex.getMessage(), ex);
            }
        }

        return result;
    }


//    /**
//     * 发送二人文字信息
//     * 
//     * @param fromUserId 发送人用户 Id
//     * @param toUserId 接收用户 Id
//     * @param message 文字消息内容
//     * @return
//     * @throws RongAuthException
//     */
//    public void sendTextMessage(long fromUserId, long toUserId, String message) throws RongAuthException {
//        Map<String, Object> json_map = Maps.newHashMap();
//        json_map.put("content", message);
//        String content = null;
//        try {
//            content = objectMapper.writeValueAsString(json_map);
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//        systemPublish(appKey, appSecret, fromUserId, Arrays.asList(toUserId), "RC:TxtMsg", content, null, null);
//    }


    // /**
    // * 发送二人自定义消息
    // *
    // * @param fromUserId 发送人用户 Id
    // * @param toUserId 接收用户 Id
    // * @param json_str 自定义内容json字符串
    // * @return
    // * @throws RongAuthException
    // */
    // public void sendFaceMessage(long fromUserId, long toUserId, String json_str) throws
    // RongAuthException {
    // systemPublish(appKey, appSecret, fromUserId, Arrays.asList(toUserId), "RC:FaceMsg", json_str,
    // null, null);
    // }

    /**
     * 服务发送系统消息给用户
     * 
     * @param pushModule
     * @param pushFunction
     * @param showTitle
     * @param showContent
     * @param content
     * @param toUserId
     * @throws RongAuthException
     */
    public void sendFaceServerMessage(String pushModule, String pushFunction, String showTitle, String showContent,
            Object content, long toUserId) {
        sendFaceMessage(pushModule, pushFunction, showTitle, showContent,
                content, serverUserId , toUserId);
    }

    /**
     * 通过某用户给另外一个用户发送消息
     * @param pushModule
     * @param pushFunction
     * @param showTitle
     * @param showContent
     * @param content
     * @param fromUserId
     * @param toUserId
     */
    public void sendFaceMessage(String pushModule, String pushFunction, String showTitle, String showContent,
            Object content,long fromUserId, long toUserId) {
        try {
            Map<String, Object> json_map = new HashMap<String, Object>();
            json_map.put("pushModule", pushModule);
            json_map.put("pushFunction", pushFunction);
            if (StringUtils.isNotBlank(showTitle)) {
                json_map.put("showTitle", showTitle);
            }
            if (StringUtils.isNotBlank(showContent)) {
                json_map.put("showContent", showContent);
            }
            json_map.put("content", content);
            //json_map.put("time", new Date());

            String json_str = null;
            try {
                json_str = null;//objectMapper.writeValueAsString(json_map);
            } catch (IOException e) {
                e.printStackTrace();
            }

            systemPublish(appKey, appSecret, fromUserId, Arrays.asList(toUserId), "RC:FaceMsg", json_str, showTitle,
                    showContent);
        } catch (Exception e) {
            logger.error("发送系统消息失败！", e);
        }
    }

//    /**
//     * 发送文字信息给所有用户
//     * 
//     * @param fromUserId 发送人用户 Id
//     * @param message 文字消息内容
//     * @return
//     * @throws RongAuthException
//     */
//    public void sendTextMessageToAll(long fromUserId, String message) throws RongAuthException {
//        Map<String, Object> json_map = Maps.newHashMap();
//        json_map.put("content", message);
//        String content = null;
//        try {
//            content = objectMapper.writeValueAsString(json_map);
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//        broadcast(appKey, appSecret, fromUserId, "RC:TxtMsg", content);
//    }
//
//    /**
//     * 发送自定义信息给所有用户
//     * 
//     * @param fromUserId 发送人用户 Id
//     * @param json_str 自定义内容json字符串
//     * @return
//     * @throws RongAuthException
//     */
//    public void sendFaceMessageToAll(long fromUserId, String json_str) throws RongAuthException {
//        broadcast(appKey, appSecret, fromUserId, "RC:FaceMsg", json_str);
//    }
    
    /**
     * 以管理员身份群发消息给所有用户
     * 
     * @param pushModule
     * @param pushFunction
     * @param showTitle
     * @param showContent
     * @param content
     * @param fromUserId
     * @throws RongAuthException
     */
    public void sendFaceServerMessageToAll(String pushModule, String pushFunction, String showTitle, String showContent,
            Object content) {
        sendFaceMessageToAll(pushModule, pushFunction, showTitle, showContent,
                content, serverUserId);
    }
    
    
    /**
     * 以某用户身份群发消息给所有用户
     * 
     * @param pushModule
     * @param pushFunction
     * @param showTitle
     * @param showContent
     * @param content
     * @param fromUserId
     * @throws RongAuthException
     */
    public void sendFaceMessageToAll(String pushModule, String pushFunction, String showTitle, String showContent,
            Object content, long fromUserId) {
        try {
            Map<String, Object> json_map = new HashMap<String, Object>();
            json_map.put("pushModule", pushModule);
            json_map.put("pushFunction", pushFunction);
            if (StringUtils.isNotBlank(showTitle)) {
                json_map.put("showTitle", showTitle);
            }
            if (StringUtils.isNotBlank(showContent)) {
                json_map.put("showContent", showContent);
            }
            json_map.put("content", content);

            String json_str = null;
            try {
                json_str = null;//objectMapper.writeValueAsString(json_map);
            } catch (IOException e) {
                e.printStackTrace();
            }

            broadcast(appKey, appSecret, fromUserId, "RC:FaceMsg", json_str, showTitle,
                    showContent);
        } catch (Exception e) {
            logger.error("发送系统消息失败！", e);
        }
    }
   

    /**
     * 创建聊天室
     * 
     * @param chatRoomId
     * @param chatRoomName
     */
    public void createChatRoom(String chatRoomId, String chatRoomName) throws RongAuthException {
        HttpClient httpclient = wrapClient(new DefaultHttpClient());

        HttpPost httppost = new HttpPost(CREATE_CHATROOM_URL);

        dealRequestHeader(httppost, appKey, appSecret);

        try {
            List<NameValuePair> nvps = new ArrayList<NameValuePair>();
            nvps.add(new BasicNameValuePair("chatroom[" + chatRoomId + "]", chatRoomName));

            httppost.setEntity(new UrlEncodedFormEntity(nvps, "UTF-8"));
            HttpResponse response = httpclient.execute(httppost);
            HttpEntity entity = response.getEntity();
            String strResultJson = EntityUtils.toString(entity);
            int statCode = response.getStatusLine().getStatusCode();
            if (statCode != 200) {
                throw new RongAuthException(statCode, strResultJson, null);
            } else {
                @SuppressWarnings("rawtypes")
                Map mapResultJson = objectMapper.readValue(strResultJson, Map.class);
                int code = (int) mapResultJson.get("code");
                if (code != 200) {
                    throw new RongAuthException(code, strResultJson, null);
                }
            }

        } catch (Exception ex) {
            if (ex instanceof RongAuthException) {
                throw (RongAuthException) ex;
            } else {
                throw new RongAuthException(502, ex.getMessage(), ex);
            }
        }
    }

    /**
     * 销毁聊天室
     * 
     * @param chatRoomId
     */
    public void destroyChatRoom(String chatRoomId) throws RongAuthException {
        HttpClient httpclient = wrapClient(new DefaultHttpClient());

        HttpPost httppost = new HttpPost(DESTROY_CHATROOM_URL);

        dealRequestHeader(httppost, appKey, appSecret);

        try {
            List<NameValuePair> nvps = new ArrayList<NameValuePair>();
            nvps.add(new BasicNameValuePair("chatroomId", chatRoomId));

            httppost.setEntity(new UrlEncodedFormEntity(nvps, "UTF-8"));
            HttpResponse response = httpclient.execute(httppost);
            HttpEntity entity = response.getEntity();
            String strResultJson = EntityUtils.toString(entity);
            int statCode = response.getStatusLine().getStatusCode();
            if (statCode != 200) {
                throw new RongAuthException(statCode, strResultJson, null);
            } else {
                @SuppressWarnings("rawtypes")
                Map mapResultJson = objectMapper.readValue(strResultJson, Map.class);
                int code = (int) mapResultJson.get("code");
                if (code != 200) {
                    throw new RongAuthException(code, strResultJson, null);
                }
            }

        } catch (Exception ex) {
            if (ex instanceof RongAuthException) {
                throw (RongAuthException) ex;
            } else {
                throw new RongAuthException(502, ex.getMessage(), ex);
            }
        }
    }

    /**
     * 发送系统消息 (向一个或多个用户发送系统消息)
     * 
     * @param appKey
     * @param appSecret
     * @param fromUserId 发送人用户 Id。（必传）
     * @param toUserIds 接收用户Id，提供多个本参数可以实现向多用户发送系统消息。（必传）
     * @param content_type 消息类型，参考融云消息类型表.消息标志；可自定义消息类型。（必传）
     * @param content 发送消息内容，参考融云消息类型表.示例说明；如果 objectName 为自定义消息类型，该参数可自定义格式。（必传）
     * @param pushContent 如果为自定义消息，定义显示的 Push 内容。(可选)
     * @param pushData 针对 iOS 平台，Push 通知附加的 payload 字段，字段名为 appData。(可选)
     * @throws RongAuthException
     */
    private void systemPublish(String appKey, 
					    		String appSecret, 
					    		long fromUserId, 
					    		List<Long> toUserIds,
					            String content_type, 
					            String content, 
					            String pushContent, 
					            String pushData) 
					            		throws RongAuthException {
        HttpClient httpclient = wrapClient(new DefaultHttpClient());

        HttpPost httppost = new HttpPost(SYSTEM_PUBLISH_URL);
        // 处理请求头部验证
        dealRequestHeader(httppost, appKey, appSecret);

        try {
            // 封装发送内容
            List<NameValuePair> nvps = new ArrayList<NameValuePair>();

            // 拼接接收推送的用户列表
            if (!CollectionUtils.isEmpty(toUserIds)) {
                for (Long userId : toUserIds) {
                    nvps.add(new BasicNameValuePair("toUserId", String.valueOf(userId)));
                }
            }

            nvps.add(new BasicNameValuePair("fromUserId", String.valueOf(fromUserId)));
            nvps.add(new BasicNameValuePair("objectName", content_type));
            nvps.add(new BasicNameValuePair("content", content));
            if (pushContent != null) {
                String sendContet = null;
                if (pushContent.length() > 30) {
                    sendContet = pushContent.substring(0, 30) + "...";
                } else {
                    sendContet = pushContent;
                }
                nvps.add(new BasicNameValuePair("pushContent", sendContet));
            }
            if (pushData != null) {
                nvps.add(new BasicNameValuePair("pushData", pushData));
            }

            httppost.setEntity(new UrlEncodedFormEntity(nvps, "UTF-8"));
            // 发送请求
            HttpResponse response = httpclient.execute(httppost);
            // 获取返回结果
            HttpEntity entity = response.getEntity();
            // 转换返回结果
            String strResultJson = EntityUtils.toString(entity);
            logger.info(
                    "publish(fromUserId=[{}], toUserId=[{}], content_type=[{}], content=[{}], pushContent=[{}], pushData=[{}]) return:[{}]",
                    new Object[] {fromUserId, toUserIds, content_type, content, pushContent, pushData, strResultJson});
            // 获取返回结果响应码
            int stat_code = response.getStatusLine().getStatusCode();
            if (stat_code != 200) {
                throw new RongAuthException(stat_code, strResultJson, null);
            } else {
                @SuppressWarnings("rawtypes")
                Map mapResultJson = objectMapper.readValue(strResultJson, Map.class);
                int code = (int) mapResultJson.get("code");
                if (code != 200) {
                    throw new RongAuthException(code, strResultJson, null);
                }
            }
        } catch (Exception ex) {
            if (ex instanceof RongAuthException) {
                throw (RongAuthException) ex;
            } else {
                throw new RongAuthException(502, ex.getMessage(), ex);
            }
        }
    }

    /**
     * 广播消息给所有用户
     * 
     * @param appKey
     * @param appSecret
     * @param fromUserId
     * @param content_type 消息类型，参考融云消息类型表.消息标志；可自定义消息类型。（必传）
     * @param content 发送消息内容，参考融云消息类型表.示例说明；如果 objectName 为自定义消息类型，该参数可自定义格式。（必传）
     * @param pushContent 如果为自定义消息，定义显示的 Push 内容。(可选)
     * @param pushData 针对 iOS 平台，Push 通知附加的 payload 字段，字段名为 appData。(可选)
     * @return
     * @throws RongAuthException
     */
    private void broadcast(String appKey, String appSecret, long fromUserId, String content_type, String content, String pushContent, String pushData)
            throws RongAuthException {
        HttpClient httpclient = wrapClient(new DefaultHttpClient());

        HttpPost httppost = new HttpPost(BROADCAST_URL);

        dealRequestHeader(httppost, appKey, appSecret);

        try {
            List<NameValuePair> nvps = new ArrayList<NameValuePair>();
            nvps.add(new BasicNameValuePair("fromUserId", String.valueOf(fromUserId)));
            nvps.add(new BasicNameValuePair("objectName", content_type));
            nvps.add(new BasicNameValuePair("content", content));
            if (pushContent != null) {
                String sendContet = null;
                if (pushContent.length() > 30) {
                    sendContet = pushContent.substring(0, 30) + "...";
                } else {
                    sendContet = pushContent;
                }
                nvps.add(new BasicNameValuePair("pushContent", sendContet));
            }
            if (pushData != null) {
                nvps.add(new BasicNameValuePair("pushData", pushData));
            }
            
            httppost.setEntity(new UrlEncodedFormEntity(nvps, "UTF-8"));
            HttpResponse response = httpclient.execute(httppost);
            HttpEntity entity = response.getEntity();
            String strResultJson = EntityUtils.toString(entity);
            logger.info("broadcast(fromUserId=[{}], content_type=[{}], content=[{}]) return:[{}]", new Object[] {
                    fromUserId, content_type, content, strResultJson});
            int stat_code = response.getStatusLine().getStatusCode();
            if (stat_code != 200) {
                throw new RongAuthException(stat_code, strResultJson, null);
            } else {
                @SuppressWarnings("rawtypes")
                Map mapResultJson = objectMapper.readValue(strResultJson, Map.class);
                int code = (int) mapResultJson.get("code");
                if (code != 200) {
                    throw new RongAuthException(code, strResultJson, null);
                }
            }
        } catch (Exception ex) {
            if (ex instanceof RongAuthException) {
                throw (RongAuthException) ex;
            } else {
                throw new RongAuthException(502, ex.getMessage(), ex);
            }
        }
    }

    /**
     * 处理请求的头部验证信息
     * 
     * @param request
     * @param appKey
     * @param appSecret
     */
    private void dealRequestHeader(HttpUriRequest request, String appKey, String appSecret) {
        String nonce = new DecimalFormat("000000").format(random.nextInt(100000));
        String timestamp = String.valueOf(System.currentTimeMillis());

        StringBuilder toSign = new StringBuilder(appSecret).append(nonce).append(timestamp);

        request.addHeader("App-Key", appKey);
        request.addHeader("Timestamp", timestamp);
        request.addHeader("Nonce", nonce);
        request.addHeader("Signature", hexSHA1(toSign.toString()));
        request.addHeader("Content-Type", "Application/x-www-form-urlencoded");
    }

    private String hexSHA1(String value) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(value.getBytes("utf-8"));
            byte[] digest = md.digest();
            return byteToHexString(digest);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private String byteToHexString(byte[] bytes) {
        String stmp = "";
        StringBuilder sb = new StringBuilder("");
        for (int n = 0; n < bytes.length; n++) {
            stmp = Integer.toHexString(bytes[n] & 0xFF);
            sb.append((stmp.length() == 1) ? "0" + stmp : stmp);
        }
        return sb.toString().toUpperCase().trim();
    }

    public static HttpClient wrapClient(HttpClient base) {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            X509TrustManager tm = new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}

                public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
            };
            ctx.init(null, new TrustManager[] {tm}, null);
            SSLSocketFactory ssf = new SSLSocketFactory(ctx, SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
            base.getConnectionManager().getSchemeRegistry().register(new Scheme("https", 443, ssf));
            return base;
        } catch (Exception ex) {
            return base;
        }
    }
}
