package com.xxl.sso.core.filter;

import com.xxl.sso.core.conf.Conf;
import com.xxl.sso.core.entity.ReturnT;
import com.xxl.sso.core.login.SsoTokenLoginHelper;
import com.xxl.sso.core.path.impl.AntPathMatcher;
import com.xxl.sso.core.user.XxlSsoUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * app sso filter
 * Token 过滤器
 * 继承了 HttpServlet 并实现了 Filter 接口
 * @author xuxueli 2018-04-08 21:30:54
 */
public class XxlSsoTokenFilter extends HttpServlet implements Filter {
    // 日志
    private static Logger logger = LoggerFactory.getLogger(XxlSsoTokenFilter.class);

    // AntPath 匹配器初始化
    private static final AntPathMatcher antPathMatcher = new AntPathMatcher();

    private String ssoServer;
    private String logoutPath;
    private String excludedPaths;

    /**
     * 初始化配置
     */
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

        // 通过 getInitParameter() 方法获取 web.xml 配置文件中
        // 为 Filter 所设置的某个名称的初始化参数值
        ssoServer = filterConfig.getInitParameter(Conf.SSO_SERVER);
        logoutPath = filterConfig.getInitParameter(Conf.SSO_LOGOUT_PATH);
        excludedPaths = filterConfig.getInitParameter(Conf.SSO_EXCLUDED_PATHS);

        logger.info("XxlSsoTokenFilter init.");
    }

    /**
     * 重写 doFilter 方法 (Filter 接口提供)
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // make url
        // 获取 Servlet 路径
        String servletPath = req.getServletPath();

        // excluded path check
        // 这个方法获取并判断排除在外的路径，调用 FilterChain.doFilter 方法
        // 将请求转发给过滤器链的下一个 Filter
        if (excludedPaths!=null && excludedPaths.trim().length()>0) {
            for (String excludedPath:excludedPaths.split(",")) {
                String uriPattern = excludedPath.trim();

                // 支持ANT表达式
                // Ant 表达式匹配成功，则转发
                if (antPathMatcher.match(uriPattern, servletPath)) {
                    // excluded path, allow
                    chain.doFilter(request, response);
                    return;
                }

            }
        }

        // logout filter
        // 用于处理登出的过滤器
        // 如果登出路径存在且与 servletPath 匹配
        if (logoutPath!=null
                && logoutPath.trim().length()>0
                && logoutPath.equals(servletPath)) {

            // logout
            SsoTokenLoginHelper.logout(req);

            // response
            res.setStatus(HttpServletResponse.SC_OK);
            res.setContentType("application/json;charset=UTF-8");
            res.getWriter().println("{\"code\":"+ReturnT.SUCCESS_CODE+", \"msg\":\"\"}");

            return;
        }

        // login filter
        // 处理登录的过滤器
        // 通过 req 取得 SsoUser 实例
        XxlSsoUser xxlUser = SsoTokenLoginHelper.loginCheck(req);
        // 为空表示不存在 SsoUser 实例，登录失败
        if (xxlUser == null) {

            // response
            res.setStatus(HttpServletResponse.SC_OK);
            res.setContentType("application/json;charset=UTF-8");
            res.getWriter().println("{\"code\":"+Conf.SSO_LOGIN_FAIL_RESULT.getCode()+", \"msg\":\""+ Conf.SSO_LOGIN_FAIL_RESULT.getMsg() +"\"}");
            return;
        }

        // ser sso user
        // 在 request 中传入 SsoUser 对象
        request.setAttribute(Conf.SSO_USER, xxlUser);


        // already login, allow
        // 继续转发
        chain.doFilter(request, response);
        return;
    }


}
