package de.theit.jenkins.crowd.robot;

import org.acegisecurity.GrantedAuthority;

public class RobotGrantedAuthority implements GrantedAuthority {

    private static final long serialVersionUID = 3916685582699638340L;

    private String groupName;

    public RobotGrantedAuthority(final String groupName) {
        this.groupName = groupName;
    }

    @Override
    public String getAuthority() {
        return groupName;
    }

}
