/*
 * @(#)CrowdConfigurationService.java
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

import static de.theit.jenkins.crowd.ErrorMessages.applicationPermission;
import static de.theit.jenkins.crowd.ErrorMessages.groupNotFound;
import static de.theit.jenkins.crowd.ErrorMessages.invalidAuthentication;
import static de.theit.jenkins.crowd.ErrorMessages.operationFailed;
import static de.theit.jenkins.crowd.ErrorMessages.userNotFound;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;

import com.atlassian.crowd.exception.ApplicationAccessDeniedException;
import com.atlassian.crowd.exception.ApplicationPermissionException;
import com.atlassian.crowd.exception.ExpiredCredentialException;
import com.atlassian.crowd.exception.GroupNotFoundException;
import com.atlassian.crowd.exception.InactiveAccountException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.InvalidTokenException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;
import com.atlassian.crowd.integration.http.CrowdHttpAuthenticator;
import com.atlassian.crowd.integration.http.CrowdHttpAuthenticatorImpl;
import com.atlassian.crowd.integration.http.util.CrowdHttpTokenHelper;
import com.atlassian.crowd.integration.http.util.CrowdHttpTokenHelperImpl;
import com.atlassian.crowd.integration.http.util.CrowdHttpValidationFactorExtractorImpl;
import com.atlassian.crowd.integration.rest.service.factory.RestCrowdClientFactory;
import com.atlassian.crowd.model.authentication.ValidationFactor;
import com.atlassian.crowd.model.group.Group;
import com.atlassian.crowd.model.user.User;
import com.atlassian.crowd.service.client.ClientProperties;
import com.atlassian.crowd.service.client.ClientPropertiesImpl;
import com.atlassian.crowd.service.client.CrowdClient;

import de.theit.jenkins.crowd.robot.RoboticSingleton;
import hudson.util.Secret;

/**
 * This class contains all objects that are necessary to access the REST services on the remote
 * Crowd server. Additionally it contains some helper methods to check for group membership and
 * availability.
 *
 * @author <a href="mailto:theit@gmx.de">Thorsten Heit (theit@gmx.de)</a>
 * @version $Id$
 * @since 08.09.2011
 */
public class CrowdConfigurationService {
    /**
     * Used for logging purposes.
     */
    private static final Logger LOG = Logger.getLogger(CrowdConfigurationService.class.getName());

    private static final RoboticSingleton BOT = RoboticSingleton.getBot();

    /**
     * The maximum number of groups that can be fetched from the Crowd server for a user in one
     * request.
     */
    private static final int MAX_GROUPS = 500;

    /**
     * Holds the Crowd client properties.
     */
    private final ClientProperties clientProperties;

    /**
     * The Crowd client to access the REST services on the remote Crowd server.
     */
    private final CrowdClient crowdClient;

    /**
     * The helper class for Crowd SSO token operations.
     */
    private final CrowdHttpTokenHelper tokenHelper;

    /**
     * The interface used to manage HTTP authentication and web/SSO authentication integration.
     */
    private final CrowdHttpAuthenticator crowdHttpAuthenticator;

    /**
     * The names of all user groups that are allowed to login.
     */
    private final ArrayList<String> allowedGroupNames;

    /**
     * Specifies whether nested groups may be used.
     */
    private final boolean nestedGroups;

    private final boolean useSSO;

    private final boolean useCache;

    private final Integer cacheSize;

    private final Integer cacheTTL;

    private transient Map<String, CacheEntry<Boolean>> isGroupMemberCache = null;

    private transient Map<String, CacheEntry<User>> userFromSSOTokenCache = null;

    private transient Map<String, CacheEntry<User>> userCache = null;

    private transient Map<String, CacheEntry<Group>> groupCache = null;

    private transient Map<String, CacheEntry<Collection<GrantedAuthority>>> authoritiesForUserCache = null;

    /**
     * Creates a new Crowd configuration object.
     *
     * @param url
     *            The Crowd URL
     * @param applicationName
     *            The Crowd application name
     * @param password
     *            The Crowd application password
     * @param sessionValidationInterval
     *            The session validation interval
     * @param useSSO
     *            Specifies if SSO should be enabled
     * @param cookieDomain
     *            The cookie domain
     * @param cookieTokenkey
     *            The cookie token key
     * @param useProxy
     *            the Specifies if a proxy should be used
     * @param httpProxyHost
     *            The http proxy host
     * @param httpProxyPort
     *            The http proxy port
     * @param httpProxyUsername
     *            The http proxy username
     * @param httpProxyPassword
     *            The http proxy password
     * @param socketTimeout
     *            The socket timeout
     * @param httpTimeout
     *            The http timeout
     * @param httpMaxConnections
     *            The http max connections
     * @param useCache
     *            The use cache
     * @param cacheSize
     *            the cache size
     * @param cacheTTL
     *            The cache TTL
     * @param pGroupNames
     *            The group names to use when authenticating Crowd users. May not be
     *            <code>null</code>.
     * @param pNestedGroups
     *            Specifies whether nested groups should be used when validating users against a
     *            group name.
     */
    public CrowdConfigurationService(final String url, final String applicationName, final Secret password,
            final int sessionValidationInterval, final boolean useSSO,
            final String cookieDomain, final String cookieTokenkey, final Boolean useProxy,
            final String httpProxyHost, final String httpProxyPort, final String httpProxyUsername,
            final Secret httpProxyPassword, final String socketTimeout,
            final String httpTimeout, final String httpMaxConnections,
            final boolean useCache, final Integer cacheSize, final Integer cacheTTL,
            final String pGroupNames, final boolean pNestedGroups) {

        if (LOG.isLoggable(Level.INFO)) {
            LOG.info("Groups given for Crowd configuration service: " + pGroupNames);
        }
        this.allowedGroupNames = new ArrayList<String>();
        for (String group : pGroupNames.split(",")) {
            group = group.trim();
            if (group.length() > 0) {
                if (LOG.isLoggable(Level.FINE)) {
                    LOG.fine("-> adding allowed group name: " + group);
                }
                this.allowedGroupNames.add(group);
            }
        }
        this.nestedGroups = pNestedGroups;
        this.useSSO = useSSO;
        this.useCache = useCache;
        this.cacheSize = cacheSize;
        this.cacheTTL = cacheTTL;
        Properties props = getProperties(url, applicationName, Secret.toString(password), sessionValidationInterval,
            useSSO, cookieDomain, cookieTokenkey, useProxy, httpProxyHost, httpProxyPort, httpProxyUsername,
            Secret.toString(httpProxyPassword), socketTimeout, httpTimeout, httpMaxConnections);
        this.clientProperties = ClientPropertiesImpl.newInstanceFromProperties(props);
        this.crowdClient = new RestCrowdClientFactory().newInstance(this.clientProperties);
        this.tokenHelper = CrowdHttpTokenHelperImpl.getInstance(CrowdHttpValidationFactorExtractorImpl.getInstance());
        this.crowdHttpAuthenticator = new CrowdHttpAuthenticatorImpl(
                this.crowdClient,
                this.clientProperties,
                this.tokenHelper);
    }

    public ArrayList<String> getAllowedGroupNames() {
        return allowedGroupNames;
    }

    public boolean isUseSSO() {
        return useSSO;
    }

    /**
     * Checks whether the user is a member of one of the Crowd groups whose members are allowed to
     * login.
     *
     * @param username
     *            The name of the user to check. May not be <code>null</code> or empty.
     * @return <code>true</code> if and only if the group exists, is active and the user is either a
     *         direct group member or, if nested groups may be used, a nested group member.
     *         <code>false</code> else.
     */
    public boolean isGroupMember(final String username) {
        if (username == null) {
            return false; // prevent NPE
        }
        if (allowedGroupNames.isEmpty()) {
            return true;
        }
        // Load the entry from cache
        Boolean cachedRep;
        if (useCache) {
            final CacheEntry<Boolean> cached;
            synchronized (this) {
                cached = isGroupMemberCache != null ? isGroupMemberCache.get(username) : null;
            }
            if (cached != null && cached.isValid()) {
                cachedRep = cached.getValue();
            } else {
                cachedRep = null;
            }
        } else {
            cachedRep = null;
        }
        Boolean retval = false;
        if (cachedRep != null) {
            retval = cachedRep;
        } else {
            try {
                for (String group : this.allowedGroupNames) {
                    retval = isGroupMember(username, group);
                    if (retval) {
                        break;
                    }
                }
            } catch (ApplicationPermissionException ex) {
                LOG.warning(applicationPermission());
                retval = null;
            } catch (InvalidAuthenticationException ex) {
                LOG.warning(invalidAuthentication());
                retval = null;
            } catch (OperationFailedException ex) {
                LOG.log(Level.SEVERE, operationFailed(), ex);
                retval = null;
            }
        }
        // Let's save the entry in the cache if necessary
        if (useCache && cachedRep == null && retval != null) {
            synchronized (this) {
                if (isGroupMemberCache == null) {
                    isGroupMemberCache = new CacheMap<String, Boolean>(cacheSize);
                }
                isGroupMemberCache.put(username, new CacheEntry<Boolean>(cacheTTL, retval));
            }
        }
        return retval;
    }

    /**
     * Checks if the specified group name exists on the remote Crowd server and is active.
     *
     * @param groupName
     *            The name of the group to check. May not be <code>null</code> or empty.
     * @return <code>true</code> if and only if the group name is not empty, does exist on the
     *         remote Crowd server and is active. <code>false</code> else.
     * @throws InvalidAuthenticationException
     *             If the application and password are not valid.
     * @throws ApplicationPermissionException
     *             If the application is not permitted to perform the requested operation on the
     *             server
     * @throws OperationFailedException
     *             If the operation has failed for any other reason, including invalid arguments and
     *             the operation not being supported on the server.
     */
    public boolean isGroupActive(final String groupName)
            throws InvalidAuthenticationException,
            ApplicationPermissionException, OperationFailedException {
        boolean retval = false;

        try {
            if (LOG.isLoggable(Level.FINE)) {
                LOG.fine("Checking whether group is active: " + groupName);
            }
            Group group = getGroup(groupName);
            if (null != group) {
                retval = group.isActive();
            }
        } catch (GroupNotFoundException ex) {
            if (LOG.isLoggable(Level.FINE)) {
                LOG.fine(groupNotFound(groupName));
            }
        }

        return retval;
    }

    /**
     * Retrieves the list of all (nested) groups from the Crowd server that the user is a member of.
     *
     * @param username
     *            The name of the user. May not be <code>null</code>.
     * @return The list of all groups that the user is a member of. Always non-null.
     */
    public Collection<GrantedAuthority> getAuthoritiesForUser(final String username) {
        if (BOT.isRoboticUser(username)) {
            return BOT.getAuthorityList();
        }
        // Load the entry from cache
        Collection<GrantedAuthority> cachedRep;
        if (useCache) {
            final CacheEntry<Collection<GrantedAuthority>> cached;
            synchronized (this) {
                cached = authoritiesForUserCache != null ? authoritiesForUserCache.get(username) : null;
            }
            if (cached != null && cached.isValid()) {
                cachedRep = cached.getValue();
            } else {
                cachedRep = null;
            }
        } else {
            cachedRep = null;
        }
        Collection<GrantedAuthority> authorities;
        if (cachedRep != null) {
            authorities = cachedRep;
        } else {
            authorities = new TreeSet<GrantedAuthority>(
                    new Comparator<GrantedAuthority>() {
                        @Override
                        public int compare(final GrantedAuthority ga1,
                                final GrantedAuthority ga2) {
                            return ga1.getAuthority().compareTo(ga2.getAuthority());
                        }
                    });
            HashSet<String> groupNames = new HashSet<String>();

            // retrieve the names of all groups the user is a directly or indirectly member of
            // if this configuration setting is active/enabled
            if (this.nestedGroups) {
                try {
                    int index = 0;
                    if (LOG.isLoggable(Level.FINE)) {
                        LOG.fine("Retrieve list of groups with nested membership for user '"
                                + username + "'...");
                    }
                    while (true) {
                        if (LOG.isLoggable(Level.FINEST)) {
                            LOG.finest("Fetching groups [" + index + "..."
                                    + (index + MAX_GROUPS - 1) + "]...");
                        }
                        List<Group> groups = getGroupsForNestedUser(username, index, MAX_GROUPS);
                        if (null == groups || groups.isEmpty()) {
                            break;
                        }
                        for (Group group : groups) {
                            if (group.isActive()) {
                                groupNames.add(group.getName());
                            }
                        }
                        index += MAX_GROUPS;
                    }
                } catch (UserNotFoundException ex) {
                    if (LOG.isLoggable(Level.INFO)) {
                        LOG.info(userNotFound(username));
                    }
                } catch (InvalidAuthenticationException ex) {
                    LOG.warning(invalidAuthentication());
                } catch (ApplicationPermissionException ex) {
                    LOG.warning(applicationPermission());
                } catch (OperationFailedException ex) {
                    LOG.log(Level.SEVERE, operationFailed(), ex);
                }
            } else {
                // retrieve the names of all groups the user is a direct member of
                try {
                    int index = 0;
                    if (LOG.isLoggable(Level.FINE)) {
                        LOG.fine("Retrieve list of groups with direct membership for user '"
                                + username + "'...");
                    }
                    while (true) {
                        if (LOG.isLoggable(Level.FINEST)) {
                            LOG.finest("Fetching groups [" + index + "..."
                                    + (index + MAX_GROUPS - 1) + "]...");
                        }
                        List<Group> groups = getGroupsForUser(
                            username, index, MAX_GROUPS);
                        if (null == groups || groups.isEmpty()) {
                            break;
                        }
                        for (Group group : groups) {
                            if (group.isActive()) {
                                groupNames.add(group.getName());
                            }
                        }
                        index += MAX_GROUPS;
                    }
                } catch (UserNotFoundException ex) {
                    if (LOG.isLoggable(Level.INFO)) {
                        LOG.info(userNotFound(username));
                    }
                } catch (InvalidAuthenticationException ex) {
                    LOG.warning(invalidAuthentication());
                } catch (ApplicationPermissionException ex) {
                    LOG.warning(applicationPermission());
                } catch (OperationFailedException ex) {
                    LOG.log(Level.SEVERE, operationFailed(), ex);
                }
            }

            // now create the list of authorities
            for (String str : groupNames) {
                authorities.add(new GrantedAuthorityImpl(str));
            }
        }
        // Let's save the entry in the cache if necessary
        if (useCache && cachedRep == null && authorities != null) {
            synchronized (this) {
                if (authoritiesForUserCache == null) {
                    authoritiesForUserCache = new CacheMap<String, Collection<GrantedAuthority>>(cacheSize);
                }
                authoritiesForUserCache.put(username, new CacheEntry<Collection<GrantedAuthority>>(cacheTTL, authorities));
            }
        }
        return authorities;
    }

    public User authenticateUser(final String login, final String password) throws UserNotFoundException, InactiveAccountException,
            ExpiredCredentialException, ApplicationPermissionException, InvalidAuthenticationException, OperationFailedException {
        if (LOG.isLoggable(Level.FINEST)) {
            LOG.finest("CrowdClient.authenticateUser()");
        }
        if (BOT.isRoboticUser(login, password)) {
            return BOT.getUser();
        }
        return crowdClient.authenticateUser(login, password);
    }

    public User getUser(final String username)
            throws UserNotFoundException, OperationFailedException, ApplicationPermissionException, InvalidAuthenticationException {
        if (BOT.isRoboticUser(username)) {
            return BOT.getUser();
        }

        // Load the entry from cache
        User cachedRep;
        if (useCache) {
            final CacheEntry<User> cached;
            synchronized (this) {
                cached = userCache != null ? userCache.get(username) : null;
            }
            if (cached != null && cached.isValid()) {
                cachedRep = cached.getValue();
            } else {
                cachedRep = null;
            }
        } else {
            cachedRep = null;
        }
        User retval;
        if (cachedRep != null) {
            retval = cachedRep;
        } else {
            if (LOG.isLoggable(Level.FINEST)) {
                LOG.finest("CrowdClient.getUser()");
            }
            retval = crowdClient.getUser(username);
        }
        // Let's save the entry in the cache if necessary
        if (useCache && cachedRep == null && retval != null) {
            synchronized (this) {
                if (userCache == null) {
                    userCache = new CacheMap<String, User>(cacheSize);
                }
                userCache.put(username, new CacheEntry<User>(cacheTTL, retval));
            }
        }
        return retval;
    }

    public Group getGroup(final String name)
            throws GroupNotFoundException, OperationFailedException, InvalidAuthenticationException, ApplicationPermissionException {
        // Load the entry from cache
        Group cachedRep;
        if (useCache) {
            final CacheEntry<Group> cached;
            synchronized (this) {
                cached = groupCache != null ? groupCache.get(name) : null;
            }
            if (cached != null && cached.isValid()) {
                cachedRep = cached.getValue();
            } else {
                cachedRep = null;
            }
        } else {
            cachedRep = null;
        }
        Group retval;
        if (cachedRep != null) {
            retval = cachedRep;
        } else {
            if (LOG.isLoggable(Level.FINEST)) {
                LOG.finest("CrowdClient.getGroup()");
            }
            retval = crowdClient.getGroup(name);
        }
        // Let's save the entry in the cache if necessary
        if (useCache && cachedRep == null && retval != null) {
            synchronized (this) {
                if (groupCache == null) {
                    groupCache = new CacheMap<String, Group>(cacheSize);
                }
                groupCache.put(name, new CacheEntry<Group>(cacheTTL, retval));
            }
        }
        return retval;
    }

    public List<Group> getGroupsForNestedUser(final String username, final int start, final int size)
            throws OperationFailedException, InvalidAuthenticationException, ApplicationPermissionException, UserNotFoundException {
        if (LOG.isLoggable(Level.FINEST)) {
            LOG.finest("CrowdClient.getGroupsForNestedUser()");
        }
        return crowdClient.getGroupsForNestedUser(username, start, size);
    }

    public List<Group> getGroupsForUser(final String username, final int start, final int size)
            throws OperationFailedException, InvalidAuthenticationException, ApplicationPermissionException, UserNotFoundException {
        if (LOG.isLoggable(Level.FINEST)) {
            LOG.finest("CrowdClient.getGroupsForUser()");
        }
        return crowdClient.getGroupsForUser(username, start, size);
    }

    public boolean isUserDirectGroupMember(final String username, final String groupname)
            throws OperationFailedException, ApplicationPermissionException, InvalidAuthenticationException {
        if (LOG.isLoggable(Level.FINEST)) {
            LOG.finest("CrowdClient.isUserDirectGroupMember()");
        }
        return crowdClient.isUserDirectGroupMember(username, groupname);
    }

    public boolean isUserNestedGroupMember(final String username, final String groupname)
            throws OperationFailedException, ApplicationPermissionException, InvalidAuthenticationException {
        if (LOG.isLoggable(Level.FINEST)) {
            LOG.finest("CrowdClient.isUserNestedGroupMember()");
        }
        return crowdClient.isUserNestedGroupMember(username, groupname);
    }

    public void validateSSOAuthentication(final String token, final List<ValidationFactor> list)
            throws OperationFailedException, InvalidAuthenticationException, ApplicationPermissionException, InvalidTokenException {
        if (LOG.isLoggable(Level.FINEST)) {
            LOG.finest("CrowdClient.validateSSOAuthentication()");
        }
        crowdClient.validateSSOAuthentication(token, list);
    }

    public User findUserFromSSOToken(final String token)
            throws OperationFailedException, InvalidAuthenticationException, ApplicationPermissionException, InvalidTokenException {
        // Load the entry from cache
        User cachedRep;
        if (useCache) {
            final CacheEntry<User> cached;
            synchronized (this) {
                cached = userFromSSOTokenCache != null ? userFromSSOTokenCache.get(token) : null;
            }
            if (cached != null && cached.isValid()) {
                cachedRep = cached.getValue();
            } else {
                cachedRep = null;
            }
        } else {
            cachedRep = null;
        }
        User retval;
        if (cachedRep != null) {
            retval = cachedRep;
        } else {
            if (LOG.isLoggable(Level.FINEST)) {
                LOG.finest("CrowdClient.findUserFromSSOToken()");
            }
            retval = crowdClient.findUserFromSSOToken(token);
        }
        // Let's save the entry in the cache if necessary
        if (useCache && cachedRep == null && retval != null) {
            synchronized (this) {
                if (userFromSSOTokenCache == null) {
                    userFromSSOTokenCache = new CacheMap<String, User>(cacheSize);
                }
                userFromSSOTokenCache.put(token, new CacheEntry<User>(cacheTTL, retval));
            }
        }
        return retval;
    }

    public void shutdown() {
        if (LOG.isLoggable(Level.FINEST)) {
            LOG.finest("CrowdClient.shutdown()");
        }
        crowdClient.shutdown();
    }

    public void testConnection() throws OperationFailedException, InvalidAuthenticationException, ApplicationPermissionException {
        if (LOG.isLoggable(Level.FINEST)) {
            LOG.finest("CrowdClient.testConnection()");
        }
        crowdClient.testConnection();
    }

    public String getCrowdToken(final HttpServletRequest httpServletRequest) {
        if (LOG.isLoggable(Level.FINEST)) {
            LOG.finest("TokenHelper.getCrowdToken()");
        }
        return tokenHelper.getCrowdToken(httpServletRequest, clientProperties.getCookieTokenKey());
    }

    public List<ValidationFactor> getValidationFactors(final HttpServletRequest request) {
        if (LOG.isLoggable(Level.FINEST)) {
            LOG.finest("TokenHelper.getValidationFactorExtractor().getValidationFactors()");
        }
        return tokenHelper.getValidationFactorExtractor().getValidationFactors(request);
    }

    public void logout(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse)
            throws ApplicationPermissionException, InvalidAuthenticationException, OperationFailedException {
        if (LOG.isLoggable(Level.FINEST)) {
            LOG.finest("CrowdHttpAuthenticator.logout()");
        }
        crowdHttpAuthenticator.logout(httpServletRequest, httpServletResponse);
    }

    public User authenticate(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse, final String name,
            final String credentials) throws ApplicationPermissionException, InvalidAuthenticationException, OperationFailedException,
            ApplicationAccessDeniedException, ExpiredCredentialException, InactiveAccountException, InvalidTokenException {
        if (LOG.isLoggable(Level.FINEST)) {
            LOG.finest("CrowdHttpAuthenticator.authenticate()");
        }
        return crowdHttpAuthenticator.authenticate(httpServletRequest, httpServletResponse, name, credentials);
    }

    public boolean isAuthenticated(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse)
            throws OperationFailedException {
        if (LOG.isLoggable(Level.FINEST)) {
            LOG.finest("CrowdHttpAuthenticator.isAuthenticated()");
        }
        return crowdHttpAuthenticator.isAuthenticated(httpServletRequest, httpServletResponse);
    }

    /**
     * Checks whether the user is a member of the given Crowd group.
     *
     * @param username
     *            The name of the user to check. May not be <code>null</code> or empty.
     * @param group
     *            The name of the group to check the user against. May not be <code>null</code>.
     * @return <code>true</code> if and only if the group exists, is active and the user is either a
     *         direct group member or, if nested groups may be used, a nested group member.
     *         <code>false</code> else.
     * @throws ApplicationPermissionException
     *             If the application is not permitted to perform the requested operation on the
     *             server.
     * @throws InvalidAuthenticationException
     *             If the application and password are not valid.
     * @throws OperationFailedException
     *             If the operation has failed for any other reason, including invalid arguments and
     *             the operation not being supported on the server.
     */
    private boolean isGroupMember(final String username, final String group)
            throws ApplicationPermissionException,
            InvalidAuthenticationException, OperationFailedException {
        boolean retval = false;
        if (isGroupActive(group)) {
            if (LOG.isLoggable(Level.FINE)) {
                LOG.fine("Checking group membership for user '" + username
                        + "' and group '" + group + "'...");
            }
            if (this.nestedGroups) {
                if (isUserNestedGroupMember(username, group)) {
                    retval = true;
                    if (LOG.isLoggable(Level.FINER)) {
                        LOG.finer("=> user is a nested group member");
                    }
                }
            } else {
                if (isUserDirectGroupMember(username, group)) {
                    retval = true;
                    if (LOG.isLoggable(Level.FINER)) {
                        LOG.finer("=> user is a direct group member");
                    }
                }
            }
        }
        return retval;
    }

    private Properties getProperties(final String url, final String applicationName, final String password,
            final int sessionValidationInterval, final boolean useSSO,
            final String cookieDomain, final String cookieTokenkey, final Boolean useProxy,
            final String httpProxyHost, final String httpProxyPort, final String httpProxyUsername,
            final String httpProxyPassword, final String socketTimeout,
            final String httpTimeout, final String httpMaxConnections) {
        // for
        // https://docs.atlassian.com/crowd/2.7.1/com/atlassian/crowd/service/client/ClientPropertiesImpl.html
        Properties props = new Properties();

        String crowdUrl = url;
        if (!crowdUrl.endsWith("/")) {
            crowdUrl += "/";
        }
        props.setProperty("application.name", applicationName);
        props.setProperty("application.password", password);
        props.setProperty("crowd.base.url", crowdUrl);
        props.setProperty("application.login.url", crowdUrl + "console/");
        props.setProperty("crowd.server.url", crowdUrl + "services/");
        props.setProperty("session.validationinterval", String.valueOf(sessionValidationInterval));
        // TODO move other values to jenkins web configuration
        props.setProperty("session.isauthenticated", "session.isauthenticated");
        props.setProperty("session.tokenkey", "session.tokenkey");
        props.setProperty("session.lastvalidation", "session.lastvalidation");

        if (useSSO) {
            if (cookieDomain != null && !cookieDomain.equals(""))
                props.setProperty("cookie.domain", cookieDomain);
            if (cookieTokenkey != null && !cookieTokenkey.equals(""))
                props.setProperty("cookie.tokenkey", cookieTokenkey);
        }

        if (useProxy != null && useProxy) {
            if (httpProxyHost != null && !httpProxyHost.equals(""))
                props.setProperty("http.proxy.host", httpProxyHost);
            if (httpProxyPort != null && !httpProxyPort.equals(""))
                props.setProperty("http.proxy.port", httpProxyPort);
            if (httpProxyUsername != null && !httpProxyUsername.equals(""))
                props.setProperty("http.proxy.username", httpProxyUsername);
            if (httpProxyPassword != null && !httpProxyPassword.equals(""))
                props.setProperty("http.proxy.password", httpProxyPassword);
        }

        if (socketTimeout != null && !socketTimeout.equals(""))
            props.setProperty("socket.timeout", socketTimeout);
        if (httpMaxConnections != null && !httpMaxConnections.equals(""))
            props.setProperty("http.max.connections", httpMaxConnections);
        if (httpTimeout != null && !httpTimeout.equals(""))
            props.setProperty("http.timeout", httpTimeout);

        return props;
    }

    private static class CacheEntry<T> {
        private final long expires;

        private final T value;

        public CacheEntry(final int ttlSeconds, final T value) {
            this.expires = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(ttlSeconds);
            this.value = value;
        }

        public T getValue() {
            return value;
        }

        public boolean isValid() {
            return System.currentTimeMillis() < expires;
        }
    }

    /**
     * While we could use Guava's CacheBuilder the method signature changes make using it
     * problematic. Safer to roll our own and ensure compatibility across as wide a range of Jenkins
     * versions as possible.
     *
     * @param <K>
     *            Key type
     * @param <V>
     *            Cache entry type
     */
    private static class CacheMap<K, V> extends LinkedHashMap<K, CacheEntry<V>> {

        private static final long serialVersionUID = 1L;

        private final int cacheSize;

        public CacheMap(final int cacheSize) {
            super(cacheSize + 1); // prevent realloc when hitting cache size limit
            this.cacheSize = cacheSize;
        }

        @Override
        protected boolean removeEldestEntry(final Map.Entry<K, CacheEntry<V>> eldest) {
            return size() > cacheSize || eldest.getValue() == null || !eldest.getValue().isValid();
        }
    }
}
