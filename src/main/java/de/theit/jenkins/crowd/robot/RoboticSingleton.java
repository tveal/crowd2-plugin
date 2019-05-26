package de.theit.jenkins.crowd.robot;

import static org.apache.commons.lang.StringUtils.isNotBlank;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;
import org.apache.commons.lang.StringUtils;

import com.atlassian.crowd.model.user.User;

import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;

public class RoboticSingleton {

    private static final Logger LOG = Logger.getLogger(RoboticSingleton.class.getName());

    private String roboticId;

    private String roboticSecret;

    private String roboticGroup;

    private List<GrantedAuthority> authorities = new ArrayList<>();

    private RoboticSingleton() {
        authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
    }

    private static class SingletonHelper {
        private static final RoboticSingleton INSTANCE = new RoboticSingleton();
    }

    public static RoboticSingleton getBot() {
        return SingletonHelper.INSTANCE;
    }

    public void init(final String roboticId, final String roboticSecret, final String roboticGroup) {
        if (!isIdSet()) {
            this.roboticId = roboticId;
        }
        if (!isSecretSet()) {
            this.roboticSecret = roboticSecret;
        }
        if (!isGroupSet() && isNotBlank(roboticGroup)) {
            this.roboticGroup = roboticGroup;
            authorities.add(new RobotGrantedAuthority(roboticGroup));
        }
    }

    public boolean isRoboticUser(final String user) {
        if (!StringUtils.equals(user, roboticId)) {
            LOG.info("NOT roboticId: " + user);
        }
        return isIdSet() && StringUtils.equals(user, roboticId);
    }

    public boolean isRoboticUser(final String user, final String password) {
        if (!(StringUtils.equals(user, roboticId) && StringUtils.equals(password, roboticSecret))) {
            LOG.info("NOT roboticId: " + user);
        }
        boolean isValidMatchingPassword = isSecretSet() && StringUtils.equals(password, roboticSecret);
        return isRoboticUser(user) && isValidMatchingPassword;
    }

    public boolean isRoboticGroup(final String group) {
        if (!StringUtils.equals(group, roboticGroup)) {
            LOG.info("NOT roboticGroup: " + group);
        }
        return isGroupSet() && StringUtils.equals(group, roboticGroup);
    }

    public GroupDetails getGroupDetails() {
        return new RobotGroupDetails(roboticId, roboticGroup);
    }

    public User getUser() {
        return new RobotUser(roboticId);
    }

    public List<GrantedAuthority> getAuthorityList() {
        return authorities;
    }

    public UserDetails getUserDetails() {
        return new RobotUserDetails(roboticId, roboticSecret);
    }

    private boolean isIdSet() {
        return isNotBlank(roboticId);
    }

    private boolean isSecretSet() {
        return isNotBlank(roboticSecret);
    }

    private boolean isGroupSet() {
        return isNotBlank(roboticGroup);
    }

}
