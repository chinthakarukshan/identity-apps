<%--
  ~ Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
  ~
  ~  WSO2 Inc. licenses this file to you under the Apache License,
  ~  Version 2.0 (the "License"); you may not use this file except
  ~  in compliance with the License.
  ~  You may obtain a copy of the License at
  ~
  ~    http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
  --%>
<%@ page import="org.apache.commons.lang.StringUtils" %>
<%@ page import="org.json.simple.JSONObject" %>
<%@ page import="org.owasp.encoder.Encode" %>
<%@ page import="org.wso2.carbon.core.util.SignatureUtil" %>
<%@ page import="org.wso2.carbon.identity.mgt.endpoint.util.IdentityManagementEndpointConstants" %>
<%@ page import="org.wso2.carbon.identity.mgt.endpoint.util.client.ApiException" %>
<%@ page import="org.wso2.carbon.identity.mgt.endpoint.util.client.api.NotificationApi" %>
<%@ page import="org.wso2.carbon.identity.mgt.endpoint.util.client.model.Error" %>
<%@ page import="org.wso2.carbon.identity.mgt.endpoint.util.client.model.Property" %>
<%@ page import="org.wso2.carbon.identity.mgt.endpoint.util.client.model.ResetPasswordRequest" %>
<%@ page import="org.wso2.carbon.identity.recovery.util.Utils" %>
<%@ page import="java.io.File" %>
<%@ page import="java.io.UnsupportedEncodingException" %>
<%@ page import="java.net.MalformedURLException" %>
<%@ page import="java.net.URISyntaxException" %>
<%@ page import="java.net.URL" %>
<%@ page import="java.net.URLDecoder" %>
<%@ page import="java.net.URLEncoder" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.Arrays" %>
<%@ page import="java.util.Base64" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.Map" %>
<%@ page import="static java.util.stream.Collectors.toList" %>
<%@ page import="java.util.regex.Pattern" %>
<%@ page import="static java.util.stream.Collectors.groupingBy" %>
<%@ page import="static java.util.stream.Collectors.mapping" %>
<%@ page import="javax.servlet.http.Cookie" %>

<jsp:directive.include file="includes/localize.jsp"/>

<%!
    private static String decode(final String encoded) {
        
        try {
            if (encoded == null) {
                return null;
            }
            return URLDecoder.decode(encoded, "UTF-8");
        } catch (final UnsupportedEncodingException e) {
            throw new RuntimeException("Error occurred during UTF-8 encoding", e);
        }
    }
%>

<%
    String ERROR_MESSAGE = "errorMsg";
    String ERROR_CODE = "errorCode";
    String AUTO_LOGIN_COOKIE_NAME = "ALOR";
    String PASSWORD_RESET_PAGE = "password-reset.jsp";
    String passwordHistoryErrorCode = "22001";
    String passwordPatternErrorCode = "20035";
    String confirmationKey =
            IdentityManagementEndpointUtil.getStringValue(request.getSession().getAttribute("confirmationKey"));
    String newPassword = request.getParameter("reset-password");
    String callback = request.getParameter("callback");
    String tenantDomain = request.getParameter(IdentityManagementEndpointConstants.TENANT_DOMAIN);
    boolean isUserPortalURL = false;
    String sessionDataKey = request.getParameter("sessionDataKey");
    String username = request.getParameter("username");
    boolean isAutoLoginEnable = Boolean.parseBoolean(Utils.getConnectorConfig("Recovery.AutoLogin.Enable",
            tenantDomain));
    String USER_AGENT = "User-Agent";
    String userAgent = request.getHeader(USER_AGENT);
    String X_FORWARDED_USER_AGENT = "X-Forwarded-User-Agent";
    String SERVICE_PROVIDER = "serviceProvider";
    
    if (StringUtils.isBlank(callback)) {
        callback = IdentityManagementEndpointUtil.getUserPortalUrl(
                application.getInitParameter(IdentityManagementEndpointConstants.ConfigConstants.USER_PORTAL_URL));
    }

    if (callback.equals(IdentityManagementEndpointUtil.getUserPortalUrl(application
            .getInitParameter(IdentityManagementEndpointConstants.ConfigConstants.USER_PORTAL_URL)))) {
        isUserPortalURL = true;
    }
    
    if (StringUtils.isNotBlank(newPassword)) {
        NotificationApi notificationApi = new NotificationApi();
        ResetPasswordRequest resetPasswordRequest = new ResetPasswordRequest();
        
        List<Property> properties = new ArrayList<Property>();
        Property property = new Property();
        property.setKey("callback");
        property.setValue(URLEncoder.encode(callback, "UTF-8"));
        properties.add(property);

        Property userPortalURLProperty = new Property();
        userPortalURLProperty.setKey("isUserPortalURL");
        userPortalURLProperty.setValue(String.valueOf(isUserPortalURL));
        properties.add(userPortalURLProperty);

        Property tenantProperty = new Property();
        tenantProperty.setKey(IdentityManagementEndpointConstants.TENANT_DOMAIN);
        if (tenantDomain == null) {
            tenantDomain = IdentityManagementEndpointConstants.SUPER_TENANT;
        }
        tenantProperty.setValue(URLEncoder.encode(tenantDomain, "UTF-8"));
        properties.add(tenantProperty);
        Map<String, String> localVarHeaderParams = new HashMap<>();
        localVarHeaderParams.put(X_FORWARDED_USER_AGENT, userAgent);
        
        resetPasswordRequest.setKey(confirmationKey);
        resetPasswordRequest.setPassword(newPassword);
        resetPasswordRequest.setProperties(properties);
        try {
            URL url = new URL(URLDecoder.decode(callback, "UTF-8"));
            String query = url.getQuery();
            if (StringUtils.isNotBlank(query)) {
                Map<String, List<String>> queryMap =
                        Pattern.compile("&").splitAsStream(url.getQuery())
                                .map(s -> Arrays.copyOf(s.split("="), 2))
                                .collect(groupingBy(s -> decode(s[0]), mapping(s -> decode(s[1]), toList())));
                if (queryMap.containsKey("sp")) {
                    localVarHeaderParams.put(SERVICE_PROVIDER, queryMap.get("sp").get(0));
                }
            }
            notificationApi.setPasswordPost(resetPasswordRequest,localVarHeaderParams);
    
            if (isAutoLoginEnable) {
                String queryParams = callback.substring(callback.indexOf("?") + 1);
                String[] parameterList = queryParams.split("&");
                Map<String, String> queryMap = new HashMap<>();
                for (String param : parameterList) {
                    String key = param.substring(0, param.indexOf("="));
                    String value = param.substring(param.indexOf("=") + 1);
                    queryMap.put(key, value);
                }
                sessionDataKey = queryMap.get("sessionDataKey");
                String referer = request.getHeader("referer");
                String refererParams = referer.substring(referer.indexOf("?") + 1);
                parameterList = refererParams.split("&");
                for (String param : parameterList) {
                    String key = param.substring(0, param.indexOf("="));
                    String value = param.substring(param.indexOf("=") + 1);
                    queryMap.put(key, value);
                }
                String userstoredomain = queryMap.get("userstoredomain");
                if (userstoredomain != null) {
                  username = userstoredomain + "/" + username;
                }
                String signature = Base64.getEncoder().encodeToString(SignatureUtil.doSignature(username));
                JSONObject cookieValueInJson = new JSONObject();
                cookieValueInJson.put("username", username);
                cookieValueInJson.put("signature", signature);
                Cookie cookie = new Cookie(AUTO_LOGIN_COOKIE_NAME,
                        Base64.getEncoder().encodeToString(cookieValueInJson.toString().getBytes()));
                cookie.setPath("/");
                cookie.setSecure(true);
                cookie.setMaxAge(300);
                response.addCookie(cookie);
            }
        } catch (ApiException | UnsupportedEncodingException | MalformedURLException e) {
            
            Error error = IdentityManagementEndpointUtil.buildError(e);
            IdentityManagementEndpointUtil.addErrorInformation(request, error);
            if (error != null) {
                request.setAttribute(ERROR_MESSAGE, error.getDescription());
                request.setAttribute(ERROR_CODE, error.getCode());
                if (passwordHistoryErrorCode.equals(error.getCode()) ||
                        passwordPatternErrorCode.equals(error.getCode())) {
                    String i18Resource = IdentityManagementEndpointUtil.i18n(recoveryResourceBundle, error.getCode());
                    if (!i18Resource.equals(error.getCode())) {
                        request.setAttribute(ERROR_MESSAGE, i18Resource);
                    }
                    request.setAttribute(IdentityManagementEndpointConstants.TENANT_DOMAIN, tenantDomain);
                    request.setAttribute(IdentityManagementEndpointConstants.CALLBACK, callback);
                    request.getRequestDispatcher(PASSWORD_RESET_PAGE).forward(request, response);
                    return;
                }
            }
            request.getRequestDispatcher("error.jsp").forward(request, response);
            return;
        }

    } else {
        request.setAttribute("error", true);
        request.setAttribute("errorMsg", IdentityManagementEndpointUtil.i18n(recoveryResourceBundle,
                "Password.cannot.be.empty"));
        request.setAttribute(IdentityManagementEndpointConstants.TENANT_DOMAIN, tenantDomain);
        request.getRequestDispatcher("password-reset.jsp").forward(request, response);
        return;
    }

    session.invalidate();
%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>

<!doctype html>
<html>
<head>
    <%
        File headerFile = new File(getServletContext().getRealPath("extensions/header.jsp"));
        if (headerFile.exists()) {
    %>
    <jsp:include page="extensions/header.jsp"/>
    <% } else { %>
    <jsp:directive.include file="includes/header.jsp"/>
    <% } %>
</head>
<body>
    <div class="ui tiny modal notify">
        <div class="header">
            <h4>
                <%=IdentityManagementEndpointUtil.i18n(recoveryResourceBundle, "Information")%>
            </h4>
        </div>
        <div class="content">
            <p class="ui success message">
                <%=IdentityManagementEndpointUtil.i18n(recoveryResourceBundle, "Updated.the.password.successfully")%>
            </p>
        </div>
        <div class="actions">
            <div id="closeButton" class="ui primary button cancel">
                <%=IdentityManagementEndpointUtil.i18n(recoveryResourceBundle, "Close")%>
            </div>
        </div>
    </div>

    <form id="callbackForm" name="callbackForm" method="post" action="/commonauth">
        <%
            if (username != null) {
        %>
        <div>
            <input type="hidden" name="username"
                   value="<%=Encode.forHtmlAttribute(username)%>"/>
        </div>
        <%
            }
        %>
        <%
            if (sessionDataKey != null) {
        %>
        <div>
            <input type="hidden" name="sessionDataKey"
                   value="<%=Encode.forHtmlAttribute(sessionDataKey)%>"/>
        </div>
        <%
            }
        %>
    </form>

    <!-- footer -->
    <%
        File footerFile = new File(getServletContext().getRealPath("extensions/footer.jsp"));
        if (footerFile.exists()) {
    %>
    <jsp:include page="extensions/footer.jsp"/>
    <% } else { %>
    <jsp:directive.include file="includes/footer.jsp"/>
    <% } %>

    <script type="application/javascript">
        $(document).ready(function () {

            $('.notify').modal({
                onHide: function () {
                    <%
                       try {
                       if(isAutoLoginEnable) {
                %>
                    document.callbackForm.submit();
                    <%
                           } else {
                    %>
                    location.href = "<%= IdentityManagementEndpointUtil.getURLEncodedCallback(callback)%>";
                    <%
                    }
                    } catch (URISyntaxException e) {
                        request.setAttribute("error", true);
                        request.setAttribute("errorMsg", "Invalid callback URL found in the request.");
                        request.getRequestDispatcher("error.jsp").forward(request, response);
                        return;
                    }
                    %>
                },
                blurring: true,
                detachable:true,
                closable: false,
                centered: true,
            }).modal("show");

        });
    </script>
</body>
</html>
