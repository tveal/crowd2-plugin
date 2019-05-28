package de.theit.jenkins.crowd;

import static hudson.security.SecurityRealm.AUTHENTICATED_AUTHORITY;
import static org.apache.commons.lang3.reflect.FieldUtils.writeField;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.InsufficientAuthenticationException;
import org.acegisecurity.userdetails.UserDetails;
import org.junit.Test;

import com.atlassian.crowd.model.group.Group;
import com.atlassian.crowd.model.user.User;

import de.theit.jenkins.crowd.robot.RobotGrantedAuthority;
import hudson.security.GroupDetails;
import hudson.util.Secret;

public class CrowdSecurityRealmTest {

    CrowdConfigurationService configuration = mock(CrowdConfigurationService.class);

    CrowdSecurityRealm crowdSecurityRealm;

    @Test
    public void authenticate_shouldGetUserDetails_forRobotLogin() throws Exception {
        CrowdSecurityRealmBuilder realmBuilder = new CrowdSecurityRealmBuilder();
        crowdSecurityRealm = realmBuilder.build();

        UserDetails userDetails = crowdSecurityRealm.authenticate(realmBuilder.roboticId, realmBuilder.roboticSecret);

        assertThat(userDetails.getUsername()).isEqualTo(realmBuilder.roboticId);
        assertThat(userDetails.getPassword()).isEqualTo(realmBuilder.roboticSecret);
    }

    @Test(expected = InsufficientAuthenticationException.class)
    public void authenticate_shouldThrowInsufficientAuthenticationException_forNonRobot_andNotIsGroupMember() throws Exception {
        String realUsername = "realUsername";
        String realPassword = "realPassword";

        crowdSecurityRealm = new CrowdSecurityRealmBuilder().build();

        when(configuration.isGroupMember(realUsername)).thenReturn(false);

        crowdSecurityRealm.authenticate(realUsername, realPassword);
    }

    @Test
    public void authenticate_shouldReturnCrowdUser_forValidNonRobotUser() throws Exception {
        String realUsername = "realUsername";
        String realPassword = "realPassword";
        User mockUser = mock(User.class);
        RobotGrantedAuthority realUserGroup1 = new RobotGrantedAuthority("RealUserGroup1");
        RobotGrantedAuthority realUserGroup2 = new RobotGrantedAuthority("RealUserGroup2");

        crowdSecurityRealm = new CrowdSecurityRealmBuilder().build();

        when(configuration.isGroupMember(realUsername)).thenReturn(true);
        when(configuration.authenticateUser(realUsername, realPassword)).thenReturn(mockUser);
        when(configuration.getAuthoritiesForUser(realUsername)).thenReturn(new ArrayList<GrantedAuthority>() {
            {
                add(realUserGroup1);
                add(realUserGroup2);
            }
        });

        UserDetails userDetails = crowdSecurityRealm.authenticate(realUsername, realPassword);

        assertThat(userDetails.getAuthorities()).containsExactly(AUTHENTICATED_AUTHORITY,
            realUserGroup1, realUserGroup2);
    }

    @Test
    public void loadGroupByGroupname_shouldGetGroupDetails_forRobotGroup() throws Exception {
        CrowdSecurityRealmBuilder realmBuilder = new CrowdSecurityRealmBuilder();
        crowdSecurityRealm = realmBuilder.build();

        GroupDetails groupDetails = crowdSecurityRealm.loadGroupByGroupname(realmBuilder.roboticGroup);

        assertThat(groupDetails.getName()).isEqualTo(realmBuilder.roboticGroup);
        assertThat(groupDetails.getMembers()).containsExactly(realmBuilder.roboticId);
    }

    @Test
    public void loadGroupByGroupname_shouldGetGroupDetails_forNonRobotGroup() throws Exception {
        CrowdSecurityRealmBuilder realmBuilder = new CrowdSecurityRealmBuilder();
        crowdSecurityRealm = realmBuilder.build();
        String realGroup = "my-corp-users-group";
        Group mockNestedGroup = mock(Group.class);
        String mockNestedGroupName = "thisIsCrazy";

        when(configuration.getGroup(realGroup)).thenReturn(mockNestedGroup);
        when(mockNestedGroup.getName()).thenReturn(mockNestedGroupName);

        GroupDetails groupDetails = crowdSecurityRealm.loadGroupByGroupname(realGroup);

        assertThat(groupDetails.getName()).isEqualTo(mockNestedGroupName);
        assertThat(groupDetails.getMembers()).isNull();
    }

    private class CrowdSecurityRealmBuilder {

        private String applicationName = "crowd-client-app-name";

        Secret password = null;

        int sessionValidationInterval = 20;

        String url = "https://pathto.my.crowdserver.com";

        String group = "";

        String roboticId = "jenkins-operator";

        String roboticSecret = "rAndOMgenERAteDpaSs";

        String roboticGroup = "jenkins-administrators";

        CrowdSecurityRealm build() throws IllegalAccessException {
            CrowdSecurityRealm crowdSecurityRealm = new CrowdSecurityRealm(applicationName, password, 20,
                    url, group, roboticId, roboticSecret, roboticGroup);

            writeField(crowdSecurityRealm, "configuration", configuration, true);

            return crowdSecurityRealm;
        }
    }
}
