package com.xxl.sso.core.login;

import com.xxl.sso.core.conf.Conf;
import com.xxl.sso.core.store.SsoLoginStore;
import com.xxl.sso.core.user.XxlSsoUser;
import com.xxl.sso.core.store.SsoSessionIdHelper;

import javax.servlet.http.HttpServletRequest;

/**
 * @author xuxueli 2018-11-15 15:54:40
 */
public class SsoTokenLoginHelper {

    /**
     * client login
     *
     * @param sessionId
     * @param xxlUser
     */
    public static void login(String sessionId, XxlSsoUser xxlUser) {

        String storeKey = SsoSessionIdHelper.parseStoreKey(sessionId);
        if (storeKey == null) {
            throw new RuntimeException("parseStoreKey Fail, sessionId:" + sessionId);
        }

        SsoLoginStore.put(storeKey, xxlUser);
    }

    /**
     * client logout
     *
     * @param sessionId
     */
    public static void logout(String sessionId) {

        String storeKey = SsoSessionIdHelper.parseStoreKey(sessionId);
        if (storeKey == null) {
            return;
        }

        SsoLoginStore.remove(storeKey);
    }
    /**
     * client logout
     *
     * @param request
     */
    public static void logout(HttpServletRequest request) {
        String headerSessionId = request.getHeader(Conf.SSO_SESSIONID);
        logout(headerSessionId);
    }


    /**
     * login check
     *
     * @param sessionId
     * @return
     */
    public static XxlSsoUser loginCheck(String  sessionId){
        // 从 LoginStore (redis) 中获取对应的 SsoUser 对象
        String storeKey = SsoSessionIdHelper.parseStoreKey(sessionId);
        if (storeKey == null) {
            return null;
        }
        // 从 LoginStore (redis) 中获取对应的 SsoUser 对象
        XxlSsoUser xxlUser = SsoLoginStore.get(storeKey);
        if (xxlUser != null) {
            String version = SsoSessionIdHelper.parseVersion(sessionId);
            // 版本验证
            if (xxlUser.getVersion().equals(version)) {

                // After the expiration time has passed half, Auto refresh
                // 过期时间过半则自动刷新
                if ((System.currentTimeMillis() - xxlUser.getExpireFreshTime()) > xxlUser.getExpireMinute()/2) {
                    xxlUser.setExpireFreshTime(System.currentTimeMillis());
                    SsoLoginStore.put(storeKey, xxlUser);
                }

                return xxlUser;
            }
        }
        return null;
    }


    /**
     * login check
     * 从 request头中获取 sessionID，再通过 sessionID
     * 从 redis 中取得 SsoUser 对象
     * @param request
     * @return
     */
    public static XxlSsoUser loginCheck(HttpServletRequest request){
        String headerSessionId = request.getHeader(Conf.SSO_SESSIONID);
        return loginCheck(headerSessionId);
    }


}
