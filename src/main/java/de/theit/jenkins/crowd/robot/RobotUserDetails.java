package de.theit.jenkins.crowd.robot;

import static de.theit.jenkins.crowd.robot.RoboticSingleton.getBot;

import java.util.List;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;

public class RobotUserDetails implements UserDetails {

    private static final long serialVersionUID = 7250172640537626738L;

    private String roboticId;

    private String roboticSecret;

    public RobotUserDetails(final String roboticId, final String roboticSecret) {
        this.roboticId = roboticId;
        this.roboticSecret = roboticSecret;
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        List<GrantedAuthority> authorityList = getBot().getAuthorityList();
        return authorityList.toArray(new GrantedAuthority[authorityList.size()]);
    }

    @Override
    public String getPassword() {
        return roboticSecret;
    }

    @Override
    public String getUsername() {
        return roboticId;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

}
