package de.theit.jenkins.crowd.robot;

import static de.theit.jenkins.crowd.robot.RoboticSingleton.getBot;
import static org.apache.commons.lang.reflect.FieldUtils.readDeclaredField;
import static org.apache.commons.lang.reflect.FieldUtils.writeField;
import static org.assertj.core.api.Assertions.assertThat;

import org.acegisecurity.GrantedAuthority;
import org.apache.commons.lang.reflect.FieldUtils;
import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Test;
import org.junit.platform.commons.util.ReflectionUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class RoboticSingletonTest {

    String id = "robot-username";

    String secret = "robot-password";

    String group = "robot-group";

    RoboticSingleton bot = RoboticSingleton.getBot();

    @Before
    public void setup() throws IllegalAccessException {
        String roboticIdName = "roboticId";
        String roboticSecretName = "roboticSecret";
        String roboticGroupName = "roboticGroup";
        String authoritiesName = "authorities";

        //////////////////////////////////////////////////
        // reset singleton private fields before each test
        //////////////////////////////////////////////////
        writeField(bot, roboticIdName, null, true);
        writeField(bot, roboticSecretName, null, true);
        writeField(bot, roboticGroupName, null, true);

        assertThat(readDeclaredField(bot, roboticIdName, true)).isNull();
        assertThat(readDeclaredField(bot, roboticSecretName, true)).isNull();
        assertThat(readDeclaredField(bot, roboticGroupName, true)).isNull();

        // reset the authorities with the default authenticated auth
        List<GrantedAuthority> authorities = (List<GrantedAuthority>) readDeclaredField(bot, authoritiesName, true);
        writeField(bot, authoritiesName, new ArrayList<GrantedAuthority>(Arrays.asList(authorities.get(0))), true);
    }

    @Test
    public void isRoboticUser_shouldBeTrue_whenInitUserIsSame() {
        bot.init(id, secret, group);

        assertThat(bot.isRoboticUser(id)).isTrue();
    }

    @Test
    public void isRoboticUser_shouldBeFalse_whenInitNotCalled() {
        assertThat(bot.isRoboticUser(id)).isFalse();
    }

    @Test
    public void isRoboticUser_shouldBeFalse_whenInitUserIsDifferent() {
        bot.init(id, secret, group);

        assertThat(bot.isRoboticUser("bad-robot")).isFalse();
    }

    @Test
    public void isRoboticUser_shouldBeFalse_whenInitUserIsSame_butBlank() {
        String roboticId = " ";
        bot.init(roboticId, secret, group);

        assertThat(bot.isRoboticUser(roboticId)).isFalse();
    }

    @Test
    public void isRoboticUser_shouldBeTrue_whenUserAndPassSame() {
        bot.init(id, secret, group);

        assertThat(bot.isRoboticUser(id, secret)).isTrue();
    }

    @Test
    public void isRoboticUser_shouldBeFalse_whenUserSame_butPassDiff() {
        bot.init(id, secret, group);

        assertThat(bot.isRoboticUser(id, "fake pass")).isFalse();
    }

    @Test
    public void isRoboticUser_shouldBeFalse_whenUserDiff_butPassSame() {
        bot.init(id, secret, group);

        assertThat(bot.isRoboticUser("bad-robot", secret)).isFalse();
    }

    @Test
    public void isRoboticUser_shouldBeFalse_whenUserAndPassSame_butBlankUser() {
        String blankUser = "   ";
        bot.init(blankUser, secret, group);

        assertThat(bot.isRoboticUser(blankUser, secret)).isFalse();
    }

    @Test
    public void isRoboticUser_shouldBeFalse_whenUserAndPassSame_butBlankPassword() {
        String blankPass = "    ";
        bot.init(id, secret, blankPass);

        assertThat(bot.isRoboticUser(id, blankPass)).isFalse();
    }

    @Test
    public void isRoboticUser_shouldBeFalse_whenUserAndPassSame_butNullPassword() {
        String nullPass = null;
        bot.init(id, secret, nullPass);

        assertThat(bot.isRoboticUser(id, nullPass)).isFalse();
    }

    @Test
    public void isRoboticGroup_shouldBeTrue_whenGroupSame() {
        bot.init(id, secret, group);

        assertThat(bot.isRoboticGroup(group)).isTrue();

        List<GrantedAuthority> authList = bot.getAuthorityList();
        assertThat(authList).hasSize(2);
        assertThat(authList.get(0).getAuthority()).isEqualTo("authenticated");
        assertThat(authList.get(1).getAuthority()).isEqualTo(group);
    }

    @Test
    public void isRoboticGroup_shouldBeFalse_whenGroupSame_andBlank() {
        String blankGroup = " ";
        bot.init(id, secret, blankGroup);

        assertThat(bot.isRoboticGroup(blankGroup)).isFalse();

        List<GrantedAuthority> authList = bot.getAuthorityList();
        assertThat(authList).hasSize(1);
        assertThat(authList.get(0).getAuthority()).isEqualTo("authenticated");
    }

    @Test
    public void isRoboticGroup_shouldBeFalse_whenGroupSame_andNull() {
        String nullGroup = null;
        bot.init(id, secret, nullGroup);

        assertThat(bot.isRoboticGroup(nullGroup)).isFalse();

        List<GrantedAuthority> authList = bot.getAuthorityList();
        assertThat(authList).hasSize(1);
        assertThat(authList.get(0).getAuthority()).isEqualTo("authenticated");
    }

    @Test
    public void isRoboticGroup_shouldBeFalse_whenGroupDiff() {
        bot.init(id, secret, group);

        assertThat(bot.isRoboticGroup("fake-group")).isFalse();

        List<GrantedAuthority> authList = bot.getAuthorityList();
        assertThat(authList).hasSize(2);
        assertThat(authList.get(0).getAuthority()).isEqualTo("authenticated");
        assertThat(authList.get(1).getAuthority()).isEqualTo(group);
    }

    @Test
    public void getGroupDetails_shouldGetGroupDetails_withRoboticThings() {
        bot.init(id, secret, group);

        assertThat(bot.getGroupDetails().getName()).isEqualTo(group);
        assertThat(bot.getGroupDetails().getMembers()).hasSize(1);
        assertThat(bot.getGroupDetails().getMembers()).contains(id);
    }

    @Test
    public void getUser_shouldGetUser_withRoboticThings() {
        bot.init(id, secret, group);

        assertThat(bot.getUser().getName()).isEqualTo(id);
        assertThat(bot.getUser().getDisplayName()).isEqualTo(id);
        assertThat(bot.getUser().getFirstName()).isEqualTo(id);
        assertThat(bot.getUser().getLastName()).isEqualTo("");
    }

    @Test
    public void getUserDetails_shouldGetUserDetails_withRoboticThings() {
        bot.init(id, secret, group);

        assertThat(bot.getUserDetails().getPassword()).isEqualTo(secret);
        assertThat(bot.getUserDetails().getUsername()).isEqualTo(id);
        assertThat(bot.getUserDetails().isAccountNonExpired()).isTrue();
        assertThat(bot.getUserDetails().isCredentialsNonExpired()).isTrue();
        assertThat(bot.getUserDetails().isEnabled()).isTrue();
    }
}
