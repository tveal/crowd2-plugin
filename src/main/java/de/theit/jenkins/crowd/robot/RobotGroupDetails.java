package de.theit.jenkins.crowd.robot;

import java.util.HashSet;
import java.util.Set;

import hudson.security.GroupDetails;

public class RobotGroupDetails extends GroupDetails {

    private String roboticId;

    private String roboticGroup;

    public RobotGroupDetails(final String roboticId, final String roboticGroup) {
        this.roboticId = roboticId;
        this.roboticGroup = roboticGroup;
    }

    @Override
    public String getName() {
        return roboticGroup;
    }

    @Override
    public Set<String> getMembers() {
        final Set<String> members = new HashSet<>();
        members.add(roboticId);
        return members;
    }
}
