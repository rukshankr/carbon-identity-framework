package org.wso2.carbon.identity.application.authentication.framework.handler.request.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.TransientObjectWrapper;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthResponseWrapper;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authentication.framework.util.LoginContextManagementUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Base64;
import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Demo Authentication Request Coordinator
 */
public class DemoRequestCoordinator extends DefaultRequestCoordinator {
    private static final Log log = LogFactory.getLog(DemoRequestCoordinator.class);
    private static volatile DemoRequestCoordinator instance;
    public static final String SESSION_ID = "session_id";
    public static final String DB_ENTRY_KEY = "db_entry_key";
    public static final String ID_TOKEN = "id_token";

    public static DemoRequestCoordinator getInstance() {
        if (instance == null) {
            synchronized (DemoRequestCoordinator.class) {
                if (instance == null) {
                    instance = new DemoRequestCoordinator();
                }
            }
        }
        return instance;
    }

    private DemoRequestCoordinator() {}

    public static boolean isInitialDemoFlow (HttpServletRequest request) {
        if (request.getParameter("type") != null) {
            return request.getParameter("type").contains("demo");
        }
        return false;
    }

    public static boolean isReturningDemoFlow (HttpServletRequest request) {
        if (request.getQueryString() != null) {
            return request.getQueryString().contains("demo_");
        }
        return false;
    }

    public void handle (HttpServletRequest request, HttpServletResponse response, boolean isReturningFlow)
            throws IOException {

        CommonAuthResponseWrapper responseWrapper = null;
        if (response instanceof CommonAuthResponseWrapper) {
            responseWrapper = (CommonAuthResponseWrapper) response;
        } else {
            responseWrapper = new CommonAuthResponseWrapper(response);
            responseWrapper.setWrappedByFramework(true);
        }
        String sessionDataKey = request.getParameter("sessionDataKey");
        AuthenticationContext context;

        if (isReturningFlow) {
            context = FrameworkUtils.getContextData(request);
            if (context == null) {
                log.error("Context does not exist. Probably due to invalidated cache. ");
            }
            handleDemoPostAuthorization(request, response, responseWrapper, context);

            //send FULL PAGE
            String fullPage = createFormPage("http://localhost:8080/IdPPlaygroundTester/result.jsp",
                    context.getParameter(ID_TOKEN).toString(), "success");
            response.setContentType("text/html");
            PrintWriter out = response.getWriter();
            out.print(fullPage);
            return;
//            Response.ok(createFormPage(context.getProperty("db_entry_key")))
//                    .build();
            // set redirect URL
//            request.setAttribute("db_entry_key", context.getProperty("db_entry_key"));
//            response.sendRedirect("http://localhost:8080/playground2/success.jsp"
//                    + "#dbCode="
//                    + context.getProperty("db_entry_key"));
            //cross context allow in webapp
//            String ctxtApp = "/playground2";
//            request.setAttribute("db_entry_key", context.getProperty("db_entry_key"));
//            ServletContext authEndpoint = request.getServletContext()
//                    .getContext(ctxtApp);
//            RequestDispatcher requestDispatcher = authEndpoint
//                    .getRequestDispatcher("/success.jsp");
//            try {
//                requestDispatcher.include(request, response); //include(req,res); filters
//                return;
//            } catch (ServletException e) {
//                throw new RuntimeException("IS was not able to forward to this location");
//            }
        } else {
            context = new AuthenticationContext();
            try {
                String idpName = IdentityProviderManager.getInstance()
                        .getIdPNameByResourceId(request.getParameter("idp_id"));
                context.setExternalIdP(ConfigurationFacade.getInstance()
                        .getIdPConfigByName(idpName, request.getParameter("tenantDomain")));
                context.initializeAnalyticsData();
                handleDemoPreAuthorization(request, response, responseWrapper, context);
            } catch (IdentityProviderManagementException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Get IdP Configuration By Name error.", e);
                }
            }
        }
        unwrapResponse(responseWrapper, sessionDataKey, response, context);
    }

    private String createFormPage(String pageName, String idToken, Object key) {
        String formHead = "<html>\n" +
                "   <head><title>Submit This Form</title></head>\n" +
                "   <body onload=\"javascript:document.forms[0].submit()\">\n" +
                "    <p>Click the submit button if automatic redirection failed.</p>" +
                "    <form method=\"post\" action=" + pageName + "#" + (String) key + ">\n";

        String formContent = "<input type =\"text\" name=\"idToken\" value=\"" + idToken + "\">" +
                "<input type =\"text\" name=\"decodedToken\" value=\"" + idToken + "\">";
        String formBottom = "<input type=\"submit\" value=\"Submit\">" +
                "</form>\n" +
                "</body>\n" +
                "</html>";
        StringBuilder form = new StringBuilder(formHead);
        form.append(formContent);
        form.append(formBottom);
        return form.toString();
    }

    private void handleDemoPostAuthorization (HttpServletRequest request,
                                              HttpServletResponse response,
                                              CommonAuthResponseWrapper responseWrapper,
                                              AuthenticationContext context)
            throws IOException {
        try {
            associateTransientRequestData(request, response, context);

            ApplicationAuthenticator authenticator = FrameworkUtils.getAppAuthenticatorByName(context.getExternalIdP()
                    .getIdentityProvider().getDefaultAuthenticatorConfig().getName());

            authenticator.process(request, response, context);

            UserCoreUtil.setDomainInThreadLocal(null);
            if (context != null) {
                // Mark this context left the thread. Now another thread can use this context.
                context.setActiveInAThread(false);
                if (log.isDebugEnabled()) {
                    log.debug("Context id: " + context.getContextIdentifier() + " left the thread with id: " +
                            Thread.currentThread().getId());
                }
            }

            demoConcludeFlow(request, context);
        } catch (AuthenticationFailedException | LogoutFailedException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while processing demo authentication", e);
            }
        }
    }

    private void handleDemoPreAuthorization (HttpServletRequest request,
                                            HttpServletResponse response,
                                            CommonAuthResponseWrapper responseWrapper,
                                            AuthenticationContext context)
            throws IOException {
        try {
            ApplicationAuthenticator authenticator = FrameworkUtils.getAppAuthenticatorByName(context.getExternalIdP()
                    .getIdentityProvider().getDefaultAuthenticatorConfig().getName());

            context.setAuthenticatorProperties(FrameworkUtils.getAuthenticatorPropertyMapFromIdP(
                    context.getExternalIdP(), authenticator.getName()));

            String contextId = "demo_" + authenticator.getContextIdentifier(request);
            context.setContextIdentifier(contextId);

            associateTransientRequestData(request, response, context);

            synchronizeContext(request, responseWrapper, context);

            authenticator.process(request, response, context);

            // Persist the context.
            FrameworkUtils.addAuthenticationContextToCache(context.getContextIdentifier(), context);
            if (log.isDebugEnabled()) {
                log.debug("Context with id: " + context.getContextIdentifier() + " added to the cache.");
            }
        } catch (AuthenticationFailedException | LogoutFailedException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while pre-processing demo authentication", e);
            }
        }
    }

    private void demoConcludeFlow (HttpServletRequest request, AuthenticationContext context) {
        AuthenticationResult authenticationResult = new AuthenticationResult();
        authenticationResult.setAuthenticated(true);
        authenticationResult.setSubject(context.getSubject());
        String dbEntryKey = UUIDGenerator.generateUUID();
        authenticationResult.addProperty(SESSION_ID, dbEntryKey);
        context.setProperty(DB_ENTRY_KEY, dbEntryKey);
        String idToken = context.getParameter(ID_TOKEN).toString();

        //encode the JSON user info strings
        if (isValidJSON(idToken)) {
            idToken = Base64.getEncoder().encodeToString(idToken.getBytes());
        }

        context.setProperty(ID_TOKEN, idToken);
        authenticationResult.addProperty(ID_TOKEN, idToken);
        FrameworkUtils.addAuthenticationResultToCache(dbEntryKey, authenticationResult);
        FrameworkUtils.removeAuthenticationContextFromCache(context.getContextIdentifier());
        LoginContextManagementUtil.markPostAuthenticationCompleted(context);
    }

    private void synchronizeContext(HttpServletRequest request,
                                    CommonAuthResponseWrapper responseWrapper,
                                    AuthenticationContext context) throws IOException {
        synchronized (context) {
            if (!context.isActiveInAThread()) {
                // Marks this context is active in a thread. We only allow at a single instance, a context
                // to be active in only a single thread. In other words, same context cannot active in two
                // different threads at the same time.
                context.setActiveInAThread(true);
                if (log.isDebugEnabled()) {
                    log.debug("Context id: " + context.getContextIdentifier() + " is active in the thread " +
                            "with id: " + Thread.currentThread().getId());
                }
            } else {
                log.error("Same context is currently in used by a different thread. Possible double submit.");
                if (log.isDebugEnabled()) {
                    log.debug("Same context is currently in used by a different thread. Possible double submit."
                            +  "\n" +
                            "Context id: " + context.getContextIdentifier() + "\n" +
                            "Originating address: " + request.getRemoteAddr() + "\n" +
                            "Request Headers: " + getHeaderString(request) + "\n" +
                            "Thread Id: " + Thread.currentThread().getId());
                }
                FrameworkUtils.sendToRetryPage(request, responseWrapper, context);
                return;
            }
        }
    }

    private static String getHeaderString(HttpServletRequest request) {

        Enumeration<String> headerNames = request.getHeaderNames();
        StringBuilder stringBuilder = new StringBuilder();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            stringBuilder.append("Header Name: ").append(headerName).append(", ")
                    .append("Value: ").append(request.getHeader(headerName)).append(". ");
        }
        return stringBuilder.toString();
    }

    private void associateTransientRequestData(HttpServletRequest request, HttpServletResponse response,
                                               AuthenticationContext context) {

        if (context == null) {
            return;
        }
        // set current request and response to the authentication context.
        context.setProperty(FrameworkConstants.RequestAttribute.HTTP_REQUEST, new TransientObjectWrapper(request));
        context.setProperty(FrameworkConstants.RequestAttribute.HTTP_RESPONSE, new TransientObjectWrapper(response));
    }

    private boolean isValidJSON(String idToken) {
        try {
            new JSONObject(idToken);
        } catch (JSONException e) {
            try {
                new JSONArray(idToken);
            } catch (JSONException ex) {
                return false;
            }
        }
        return true;
    }
}
