package com.company.demo.web.auth;

import com.haulmont.cuba.core.global.PasswordEncryption;
import com.haulmont.cuba.security.auth.AuthenticationService;
import com.haulmont.cuba.security.auth.LoginPasswordCredentials;
import com.haulmont.cuba.security.global.LoginException;
import com.haulmont.cuba.web.auth.CubaAuthProvider;
import org.apache.commons.lang.StringUtils;

import javax.inject.Inject;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.Principal;
import java.util.Locale;

public class SimpleTokenAuthProvider implements CubaAuthProvider {

    public static final String TOKEN_PRINCIPAL_SESSION_ATTR = "TOKEN_PRINCIPAL";

    @Inject
    private AuthenticationService authenticationService;

    @Inject
    private PasswordEncryption passwordEncryption;

    @Override
    public void authenticate(String login, String password, Locale locale) throws LoginException {
        authenticationService.authenticate(
                new LoginPasswordCredentials(login, passwordEncryption.getPlainHash(password), locale));
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // do nothing
    }

    @Override
    public void destroy() {
        // do nothing
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        // here we check request parameter and if it is a correct token, then login user as passed user name
        // http://localhost:8080/app?token=LOG_IN_ME_PLEASE&user=admin

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        // ignore static requests
        if (StringUtils.startsWith(httpRequest.getRequestURI(), httpRequest.getContextPath() + "/VAADIN/")) {
            chain.doFilter(request, response);
            return;
        }

        HttpSession session = httpRequest.getSession();
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        if (request.getParameter("user") != null
                && "LOG_IN_ME_PLEASE".equals(request.getParameter("token"))) {

            SimpleTokenPrincipalImpl sessionPrincipal = new SimpleTokenPrincipalImpl(request.getParameter("user"));
            session.setAttribute(TOKEN_PRINCIPAL_SESSION_ATTR, sessionPrincipal);
            httpResponse.sendRedirect(httpRequest.getRequestURL().toString());
            return;
        }

        SimpleTokenPrincipalImpl principal = (SimpleTokenPrincipalImpl) session.getAttribute(TOKEN_PRINCIPAL_SESSION_ATTR);
        if (principal != null) {
            HttpServletRequest authenticatedRequest = new ServletRequestWrapper(httpRequest, principal);
            chain.doFilter(authenticatedRequest, response);
            return;
        }

        chain.doFilter(request, response);
    }

    public static class ServletRequestWrapper extends HttpServletRequestWrapper {
        private final SimpleTokenPrincipalImpl principal;

        public ServletRequestWrapper(HttpServletRequest request, SimpleTokenPrincipalImpl principal) {
            super(request);
            this.principal = principal;
        }

        @Override
        public Principal getUserPrincipal() {
            return principal;
        }
    }

    public static class SimpleTokenPrincipalImpl implements Principal {
        private final String userName;

        public SimpleTokenPrincipalImpl(String userName) {
            this.userName = userName;
        }

        @Override
        public String getName() {
            return userName;
        }
    }
}