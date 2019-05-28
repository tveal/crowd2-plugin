/*
 * @(#)CrowdSecurityRealm.java
 *
 * The MIT License
 *
 * Copyright (C)2011 Thorsten Heit.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package de.theit.jenkins.crowd;

import static de.theit.jenkins.crowd.ErrorMessages.accountExpired;
import static de.theit.jenkins.crowd.ErrorMessages.applicationPermission;
import static de.theit.jenkins.crowd.ErrorMessages.expiredCredentials;
import static de.theit.jenkins.crowd.ErrorMessages.groupNotFound;
import static de.theit.jenkins.crowd.ErrorMessages.invalidAuthentication;
import static de.theit.jenkins.crowd.ErrorMessages.operationFailed;
import static de.theit.jenkins.crowd.ErrorMessages.specifyApplicationName;
import static de.theit.jenkins.crowd.ErrorMessages.specifyApplicationPassword;
import static de.theit.jenkins.crowd.ErrorMessages.specifyCrowdUrl;
import static de.theit.jenkins.crowd.ErrorMessages.specifySessionValidationInterval;
import static de.theit.jenkins.crowd.ErrorMessages.userNotFound;
import static de.theit.jenkins.crowd.ErrorMessages.userNotValid;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;

import org.acegisecurity.AccountExpiredException;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.InsufficientAuthenticationException;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.verb.POST;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataRetrievalFailureException;

import com.atlassian.crowd.exception.ApplicationPermissionException;
import com.atlassian.crowd.exception.ExpiredCredentialException;
import com.atlassian.crowd.exception.GroupNotFoundException;
import com.atlassian.crowd.exception.InactiveAccountException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;
import com.atlassian.crowd.model.group.Group;
import com.atlassian.crowd.model.user.User;

import de.theit.jenkins.crowd.robot.RoboticSingleton;
import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import jenkins.model.Jenkins;

/**
 * This class provides the security realm for authenticating users against a remote Crowd server.
 *
 * @author <a href="mailto:theit@gmx.de">Thorsten Heit (theit@gmx.de)</a>
 * @since 06.09.2011
 * @version $Id$
 */
public class CrowdSecurityRealm extends AbstractPasswordBasedSecurityRealm {

    private static final Logger LOG = Logger.getLogger(CrowdSecurityRealm.class.getName());

    private static final RoboticSingleton BOT = RoboticSingleton.getBot();

    public final String url;

    public final String applicationName;

    public final Secret password;

    public final String group;

    public final boolean nestedGroups;

    /** Don't use SSO, only REST API authentication. */
    // TODO: Currently this just disables CrowdServletFilter,
    // (auto-logout), maybe worth disabling other SSO handling too.
    public final boolean useSSO;

    /**
     * The number of minutes to cache authentication validation in the session. If this value is set
     * to 0, each HTTP request will be authenticated with the Crowd server.
     */
    public final int sessionValidationInterval;

    /**
     * A domain to use when setting cookies, overriding the SSO Domain set in Crowd (since Crowd
     * 2.5.2). cookie.domain <a href=
     * "https://confluence.atlassian.com/display/CROWD/The+crowd.properties+file">details</a>
     */
    public final String cookieDomain;

    /**
     * SSO cookie name for application. cookie.tokenkey <a href=
     * "https://confluence.atlassian.com/display/CROWD/The+crowd.properties+file">details</a>
     */
    public final String cookieTokenkey;

    public final Boolean useProxy;

    public final String httpProxyHost;

    public final String httpProxyPort;

    public final String httpProxyUsername;

    public final Secret httpProxyPassword;

    public final String socketTimeout;

    public final String httpTimeout;

    public final String httpMaxConnections;

    /**
     * @since 1.9
     */
    private final CacheConfiguration cache;

    /**
     * The configuration data necessary for accessing the services on the remote Crowd server.
     */
    transient private CrowdConfigurationService configuration;

    /**
     * Default constructor. Fields in config.jelly must match the parameter names in the
     * "DataBoundConstructor".
     */
    @DataBoundConstructor
    public CrowdSecurityRealm(
            final String applicationName,
            final Secret password,
            final int sessionValidationInterval,
            final String url,
            final String group,
            final String roboticId,
            final String roboticSecret,
            final String roboticGroup) {

        List<String> msg = new ArrayList<>();
        msg.add("Instantiating CrowdSecurityRealm with props:");
        msg.add("");
        msg.add("applicationName=" + applicationName);
        msg.add("password=" + password);
        msg.add("sessionValidationInterval=" + sessionValidationInterval);
        msg.add("url=" + url);
        msg.add("group=" + group);
        msg.add("");
        LOG.info(StringUtils.join(msg, "\n"));

        this.applicationName = applicationName;
        this.password = password;
        this.sessionValidationInterval = sessionValidationInterval;
        this.url = url;
        this.group = group;

        BOT.init(roboticId, roboticSecret, roboticGroup);

        httpProxyPassword = null;
        nestedGroups = false;
        useProxy = false;
        useSSO = false;
        cookieDomain = null;
        cookieTokenkey = null;
        httpProxyHost = null;
        httpProxyPort = null;
        httpProxyUsername = null;
        socketTimeout = null;
        httpTimeout = null;
        httpMaxConnections = null;
        cache = null;
    }

    /**
     * Default constructor. Fields in config.jelly must match the parameter names in the
     * "DataBoundConstructor".
     *
     * @param group
     *            The group to which users must belong to. If this parameter is not specified, a
     *            users group membership will not be checked.
     * @param nestedGroups
     *            <code>true</code> when nested groups may be used. <code>false</code> else.
     * @param sessionValidationInterval
     *            The number of minutes to cache authentication validation in the session. If this
     *            value is set to <code>0</code>, each HTTP request will be authenticated with the
     *            Crowd server.
     */
    // @DataBoundConstructor
    public CrowdSecurityRealm(final String url, final String applicationName, final Secret password, final String group,
            final boolean nestedGroups,
            final int sessionValidationInterval, final boolean useSSO, final String cookieDomain,
            final String cookieTokenkey, final Boolean useProxy, final String httpProxyHost, final String httpProxyPort,
            final String httpProxyUsername, final Secret httpProxyPassword, final String socketTimeout,
            final String httpTimeout, final String httpMaxConnections, final CacheConfiguration cache,
            final String roboticId, final String roboticSecret, final String roboticGroup) {
        this.cookieTokenkey = cookieTokenkey;
        this.useProxy = useProxy;
        this.httpProxyHost = httpProxyHost;
        this.httpProxyPort = httpProxyPort;
        this.httpProxyUsername = httpProxyUsername;
        this.httpProxyPassword = httpProxyPassword;
        this.socketTimeout = socketTimeout;
        this.httpTimeout = httpTimeout;
        this.httpMaxConnections = httpMaxConnections;
        this.url = url.trim();
        this.applicationName = applicationName.trim();
        this.password = password;
        this.group = group.trim();
        this.nestedGroups = nestedGroups;
        this.sessionValidationInterval = sessionValidationInterval;
        this.useSSO = useSSO;
        this.cookieDomain = cookieDomain;
        this.cache = cache;

        BOT.init(roboticId, roboticSecret, roboticGroup);
    }

    public CacheConfiguration getCache() {
        return cache;
    }

    public Integer getCacheSize() {
        return cache == null ? null : cache.getSize();
    }

    public Integer getCacheTTL() {
        return cache == null ? null : cache.getTtl();
    }

    private void initializeConfiguration() {
        configuration = new CrowdConfigurationService(
                url, applicationName, password, sessionValidationInterval,
                useSSO, cookieDomain, cookieTokenkey, useProxy, httpProxyHost, httpProxyPort, httpProxyUsername,
                httpProxyPassword, socketTimeout, httpTimeout, httpMaxConnections,
                cache != null, getCacheSize(), getCacheTTL(),
                group, nestedGroups);
    }

    /**
     * {@inheritDoc}
     *
     * @see hudson.security.SecurityRealm#createSecurityComponents()
     */
    @Override
    public SecurityComponents createSecurityComponents() {
        if (null == configuration) {
            initializeConfiguration();
        }

        AuthenticationManager crowdAuthenticationManager = new CrowdAuthenticationManager(configuration);
        UserDetailsService crowdUserDetails = new CrowdUserDetailsService(configuration);

        if (useSSO) {
            CrowdRememberMeServices ssoService = new CrowdRememberMeServices(configuration);
            return new SecurityComponents(crowdAuthenticationManager, crowdUserDetails, ssoService);
        } else {
            return new SecurityComponents(crowdAuthenticationManager, crowdUserDetails);
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see hudson.security.SecurityRealm#doLogout(org.kohsuke.stapler.StaplerRequest,
     *      org.kohsuke.stapler.StaplerResponse)
     */
    @Override
    public void doLogout(final StaplerRequest req, final StaplerResponse rsp)
            throws IOException, ServletException {
        SecurityRealm realm = Jenkins.getInstance().getSecurityRealm();

        if (useSSO) {
            if (realm instanceof CrowdSecurityRealm
                    && realm.getSecurityComponents().rememberMe instanceof CrowdRememberMeServices) {
                ((CrowdRememberMeServices) realm.getSecurityComponents().rememberMe).logout(req, rsp);
            }
        }

        super.doLogout(req, rsp);
    }

    /**
     * {@inheritDoc}
     *
     * @see hudson.security.SecurityRealm#createFilter(javax.servlet.FilterConfig)
     */
    @Override
    public Filter createFilter(final FilterConfig filterConfig) {
        if (null == this.configuration) {
            initializeConfiguration();
        }

        Filter defaultFilter = super.createFilter(filterConfig);

        if (!useSSO) {
            return defaultFilter;
        }

        return new CrowdServletFilter(this, this.configuration, defaultFilter);
    }

    /**
     * {@inheritDoc}
     *
     * @see hudson.security.AbstractPasswordBasedSecurityRealm#loadUserByUsername(java.lang.String)
     */
    @Override
    public UserDetails loadUserByUsername(final String username)
            throws UsernameNotFoundException, DataAccessException {
        if (BOT.isRoboticUser(username)) {
            return BOT.getUserDetails();
        }
        return getSecurityComponents().userDetails.loadUserByUsername(username);
    }

    /**
     * {@inheritDoc}
     *
     * @see hudson.security.SecurityRealm#loadGroupByGroupname(java.lang.String)
     */
    @Override
    public GroupDetails loadGroupByGroupname(final String groupname)
            throws UsernameNotFoundException, DataAccessException {

        if (BOT.isRoboticGroup(groupname)) {
            return BOT.getGroupDetails();
        }
        try {
            // load the user object from the remote Crowd server
            if (LOG.isLoggable(Level.FINER)) {
                LOG.finer("Trying to load group: " + groupname);
            }
            final Group crowdGroup = this.configuration.getGroup(groupname);

            return new GroupDetails() {
                @Override
                public String getName() {
                    return crowdGroup.getName();
                }
            };
        } catch (GroupNotFoundException ex) {
            if (LOG.isLoggable(Level.INFO)) {
                LOG.info(groupNotFound(groupname));
            }
            throw new DataRetrievalFailureException(groupNotFound(groupname), ex);
        } catch (ApplicationPermissionException ex) {
            LOG.warning(applicationPermission());
            throw new DataRetrievalFailureException(applicationPermission(), ex);
        } catch (InvalidAuthenticationException ex) {
            LOG.warning(invalidAuthentication());
            throw new DataRetrievalFailureException(invalidAuthentication(), ex);
        } catch (OperationFailedException ex) {
            LOG.log(Level.SEVERE, operationFailed(), ex);
            throw new DataRetrievalFailureException(operationFailed(), ex);
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see hudson.security.AbstractPasswordBasedSecurityRealm#authenticate(java.lang.String,
     *      java.lang.String)
     */
    @Override
    protected UserDetails authenticate(final String pUsername, final String pPassword)
            throws AuthenticationException {
        if (BOT.isRoboticUser(pUsername, pPassword)) {
            return BOT.getUserDetails();
        }
        // ensure that the group is available, active and that the user
        // is a member of it
        if (!this.configuration.isGroupMember(pUsername)) {
            throw new InsufficientAuthenticationException(userNotValid(
                pUsername, this.configuration.getAllowedGroupNames()));
        }

        User user;
        try {
            // authenticate user
            if (LOG.isLoggable(Level.FINE)) {
                LOG.fine("Authenticate user '"
                        + pUsername
                        + "' using password '"
                        + (null != pPassword ? "<available>'"
                                : "<not specified>'"));
            }
            user = this.configuration.authenticateUser(pUsername, pPassword);
        } catch (UserNotFoundException ex) {
            if (LOG.isLoggable(Level.INFO)) {
                LOG.info(userNotFound(pUsername));
            }
            throw new BadCredentialsException(userNotFound(pUsername), ex);
        } catch (ExpiredCredentialException ex) {
            LOG.warning(expiredCredentials(pUsername));
            throw new BadCredentialsException(expiredCredentials(pUsername), ex);
        } catch (InactiveAccountException ex) {
            LOG.warning(accountExpired(pUsername));
            throw new AccountExpiredException(accountExpired(pUsername), ex);
        } catch (ApplicationPermissionException ex) {
            LOG.warning(applicationPermission());
            throw new AuthenticationServiceException(applicationPermission(),
                    ex);
        } catch (InvalidAuthenticationException ex) {
            LOG.warning(invalidAuthentication());
            throw new AuthenticationServiceException(invalidAuthentication(),
                    ex);
        } catch (OperationFailedException ex) {
            LOG.log(Level.SEVERE, operationFailed(), ex);
            throw new AuthenticationServiceException(operationFailed(), ex);
        }

        // create the list of granted authorities
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        // add the "authenticated" authority to the list of granted
        // authorities...
        authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
        // ..and all authorities retrieved from the Crowd server
        authorities.addAll(this.configuration.getAuthoritiesForUser(pUsername));

        return new CrowdUser(user, authorities);
    }

    /**
     * Descriptor for {@link CrowdSecurityRealm}. Used as a singleton. The class is marked as public
     * so that it can be accessed from views.
     *
     * @author <a href="mailto:theit@gmx.de">Thorsten Heit (theit@gmx.de)</a>
     * @since 06.09.2011 13:35:41
     * @version $Id$
     */
    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        /**
         * Default constructor.
         */
        public DescriptorImpl() {
            super(CrowdSecurityRealm.class);
        }

        /**
         * Performs on-the-fly validation of the form field 'url'.
         *
         * @param url
         *            The URL of the Crowd server.
         *
         * @return Indicates the outcome of the validation. This is sent to the browser.
         */
        public FormValidation doCheckUrl(@QueryParameter final String url) {
            if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
                return FormValidation.ok();
            }

            if (0 == url.length()) {
                return FormValidation.error(specifyCrowdUrl());
            }

            return FormValidation.ok();
        }

        /**
         * Performs on-the-fly validation of the form field 'application name'.
         *
         * @return Indicates the outcome of the validation. This is sent to the browser.
         */
        public FormValidation doCheckApplicationName(
                @QueryParameter final String applicationName) {
            if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
                return FormValidation.ok();
            }

            if (0 == applicationName.length()) {
                return FormValidation.error(specifyApplicationName());
            }

            return FormValidation.ok();
        }

        /**
         * Performs on-the-fly validation of the form field 'password'.
         *
         * @return Indicates the outcome of the validation. This is sent to the browser.
         */
        public FormValidation doCheckPassword(
                @QueryParameter final String password) {
            if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
                return FormValidation.ok();
            }

            if (0 == password.length()) {
                return FormValidation.error(specifyApplicationPassword());
            }

            return FormValidation.ok();
        }

        /**
         * Performs on-the-fly validation of the form field 'session validation interval'.
         *
         * @param sessionValidationInterval
         *            The session validation interval time in minutes.
         * @return Indicates the outcome of the validation. This is sent to the browser.
         */
        public FormValidation doCheckSessionValidationInterval(
                @QueryParameter final String sessionValidationInterval) {
            if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
                return FormValidation.ok();
            }

            try {
                if (0 == sessionValidationInterval.length()
                        || Integer.valueOf(sessionValidationInterval) < 0) {
                    return FormValidation.error(specifySessionValidationInterval());
                }
            } catch (NumberFormatException ex) {
                return FormValidation.error(specifySessionValidationInterval());
            }

            return FormValidation.ok();
        }

        /**
         * Checks whether the connection to the Crowd server can be established using the given
         * credentials.
         *
         * @return Indicates the outcome of the validation. This is sent to the browser.
         */
        @POST
        public FormValidation doTestConnection(@QueryParameter final String url, @QueryParameter final String applicationName,
                @QueryParameter final String password, @QueryParameter final String group, @QueryParameter final boolean useSSO,
                @QueryParameter final String cookieDomain, @QueryParameter final int sessionValidationInterval,
                @QueryParameter final String cookieTokenkey, @QueryParameter final Boolean useProxy,
                @QueryParameter final String httpProxyHost,
                @QueryParameter final String httpProxyPort, @QueryParameter final String httpProxyUsername,
                @QueryParameter final String httpProxyPassword, @QueryParameter final String socketTimeout,
                @QueryParameter final String httpTimeout, @QueryParameter final String httpMaxConnections) {

            // Logger log = Logger.getLogger(getClass().getName());
            Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
            CrowdConfigurationService tConfiguration = new CrowdConfigurationService(
                    url, applicationName, Secret.fromString(password), sessionValidationInterval,
                    useSSO, cookieDomain, cookieTokenkey, useProxy, httpProxyHost, httpProxyPort, httpProxyUsername,
                    Secret.fromString(httpProxyPassword), socketTimeout, httpTimeout, httpMaxConnections,
                    false, null, null,
                    group, false);

            try {
                tConfiguration.testConnection();

                // ensure that the given group names are available and active
                for (String groupName : tConfiguration.getAllowedGroupNames()) {
                    if (!tConfiguration.isGroupActive(groupName)) {
                        return FormValidation.error(groupNotFound(groupName));
                    }
                }

                return FormValidation.ok("OK");
            } catch (InvalidAuthenticationException ex) {
                LOG.log(Level.WARNING, invalidAuthentication(), ex);
                return FormValidation.error(invalidAuthentication());
            } catch (ApplicationPermissionException ex) {
                LOG.log(Level.WARNING, applicationPermission(), ex);
                return FormValidation.error(applicationPermission());
            } catch (OperationFailedException ex) {
                LOG.log(Level.SEVERE, operationFailed(), ex);
                return FormValidation.error(operationFailed());
            } finally {
                tConfiguration.shutdown();
            }
        }

        /**
         * {@inheritDoc}
         *
         * @see hudson.model.Descriptor#getDisplayName()
         */
        @Override
        public String getDisplayName() {
            return "Crowd 2";
        }
    }

    public static class CacheConfiguration extends AbstractDescribableImpl<CacheConfiguration> {
        private final int size;

        private final int ttl;

        @DataBoundConstructor
        public CacheConfiguration(final int size, final int ttl) {
            this.size = Math.max(10, Math.min(size, 1000));
            this.ttl = Math.max(30, Math.min(ttl, 3600));
        }

        public int getSize() {
            return size;
        }

        public int getTtl() {
            return ttl;
        }

        @Extension
        public static class DescriptorImpl extends Descriptor<CacheConfiguration> {

            @Override
            public String getDisplayName() {
                return "";
            }

            public ListBoxModel doFillSizeItems() {
                ListBoxModel m = new ListBoxModel();
                m.add("10");
                m.add("20");
                m.add("50");
                m.add("100");
                m.add("200");
                m.add("500");
                m.add("1000");
                return m;
            }

            public ListBoxModel doFillTtlItems() {
                ListBoxModel m = new ListBoxModel();
                // TODO use Messages (not that there were any translations before)
                m.add("30 sec", "30");
                m.add("1 min", "60");
                m.add("2 min", "120");
                m.add("5 min", "300");
                m.add("10 min", "600");
                m.add("15 min", "900");
                m.add("30 min", "1800");
                m.add("1 hour", "3600");
                return m;
            }

        }
    }
}
