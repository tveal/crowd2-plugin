package de.theit.jenkins.crowd;

import static org.assertj.core.api.Assertions.assertThat;

import org.acegisecurity.userdetails.UserDetails;
import org.junit.Test;

import hudson.util.Secret;

public class CrowdSecurityRealmTest {

    String applicationName = "crowd-client-app-name";

    Secret password = null;

    int sessionValidationInterval = 20;

    String url = "https://pathto.my.crowdserver.com";

    String group = "";

    String roboticId = "jenkins-operator";

    String roboticSecret = "rAndOMgenERAteDpaSs";

    String roboticGroup = "jenkins-administrators";

    CrowdSecurityRealm csr;

    @Test
    public void ctor_shouldGetUserDetails_forRobotLogin() {
        csr = new CrowdSecurityRealm(applicationName, password, 20,
                url, group, roboticId, roboticSecret, roboticGroup);

        UserDetails userDetails = csr.authenticate(roboticId, roboticSecret);

        assertThat(userDetails.getUsername()).isEqualTo(roboticId);
        assertThat(userDetails.getPassword()).isEqualTo(roboticSecret);
    }
}
