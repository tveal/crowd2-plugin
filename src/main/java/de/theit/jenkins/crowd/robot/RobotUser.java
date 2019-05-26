package de.theit.jenkins.crowd.robot;

import com.atlassian.crowd.model.user.User;

public class RobotUser implements User {

    private String roboticId;

    public RobotUser(final String roboticId) {
        this.roboticId = roboticId;
    }

    @Override
    public String getName() {
        return roboticId;
    }

    @Override
    public long getDirectoryId() {
        return 0;
    }

    @Override
    public int compareTo(final com.atlassian.crowd.embedded.api.User arg0) {
        return 0;
    }

    @Override
    public String getDisplayName() {
        return roboticId;
    }

    @Override
    public String getEmailAddress() {
        return null;
    }

    @Override
    public boolean isActive() {
        return true;
    }

    @Override
    public String getExternalId() {
        return null;
    }

    @Override
    public String getFirstName() {
        return roboticId;
    }

    @Override
    public String getLastName() {
        return "";
    }

}
