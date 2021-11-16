package com.xxl.sso.core.conf;

import com.xxl.sso.core.entity.ReturnT;

/**
 * conf
 * 一些定义信息
 * @author xuxueli 2018-04-02 19:18:04
 */
public class Conf {

    /**
     * sso sessionid, between browser and sso-server (web + token client)
     * 会话 ID
     */
    public static final String SSO_SESSIONID = "xxl_sso_sessionid";


    /**
     * redirect url (web client)
     * Web 客户端重定向路径
     */
    public static final String REDIRECT_URL = "redirect_url";

    /**
     * sso user, request attribute (web client)
     * SSO 用户
     */
    public static final String SSO_USER = "xxl_sso_user";


    /**
     * sso server address (web + token client)
     * SSO中心地址
     */
    public static final String SSO_SERVER = "sso_server";

    /**
     * login url, server relative path (web client)
     * Web 客户端登录路径
     */
    public static final String SSO_LOGIN = "/login";
    /**
     * logout url, server relative path (web client)
     * Web 客户端登出路径
     */
    public static final String SSO_LOGOUT = "/logout";


    /**
     * logout path, client relatice path
     * 登出路径，客户关联路径
     */
    public static final String SSO_LOGOUT_PATH = "SSO_LOGOUT_PATH";

    /**
     * excluded paths, client relatice path, include path can be set by "filter-mapping"
     */
    public static final String SSO_EXCLUDED_PATHS = "SSO_EXCLUDED_PATHS";


    /**
     * login fail result
     * 登录失败返回 Result
     */
    public static final ReturnT<String> SSO_LOGIN_FAIL_RESULT = new ReturnT(501, "sso not login.");


}
