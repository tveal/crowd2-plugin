# Robotic User for Crowd 2 Plugin

**Why?**

If you use a robotic service to manage your Jenkins master instance, such as a
[kubernetes operator](https://github.com/jenkinsci/kubernetes-operator),
this robotic service needs to be able to authenticate with the Jenkins master. If you use Crowd as
your security realm, then your robotic service may lose auth ability. Especially if your robotic
service generates it's own token/password per Jenkins master instance. Keeping this generated
token/password in-sync with your Crowd server might not be an option.

**How?**

A `RoboticSingleton` class has been added to this Crowd plugin to manage the auth of your
robotic service, _local to the Jenkins master instance_. When your configuration-as-code sets up
this plugin as the `securityRealm`, the RoboticSingleton stores the robotic creds. Whenever your
robot tries to authenticate again to the running Jenkins instance, the RoboticSingleton
compares the login creds with the initial creds. This is also useful to have for a local
admin for your Jenkins instance when your crowd server is unavailable.

## Configure Jenkins with CasC

Use [Jenkins Configuration as Code Plugin](https://github.com/jenkinsci/configuration-as-code-plugin)
to configure this mod of the Crowd 2 plugin.

```yaml
jenkins:
  securityRealm:
    crowd:
      applicationName: "${CROWD_APP_NAME}"
      password: "${CROWD_PASSWORD}"
      sessionValidationInterval: 20
      url: "https://url-to-your-crowd.server"
      group: ""
      roboticId: "${ROBOTIC_ID}"
      roboticSecret: "${ROBOTIC_SECRET}"
      roboticGroup: "jenkins-administrators"
```

## Build with Gradle

You can use the gradle wrapper in the mod to build the project. It's leveraging the
[Gradle JPI Plugin](https://github.com/jenkinsci/gradle-jpi-plugin).
To get started, build and test everything (from the root directory on this repo):

```bash
./gradlew clean build
```

You can then find the built plugin at `build/libs/crowd2.hpi`

## Install the Plugin Manually

To install the plugin manually on a Jenkins instance, place the `crowd2.hpi` in `/usr/share/jenkins/ref/plugins/`
and **rename** the extension to `.jpi` ([reference](https://github.com/jenkinsci/docker/blob/master/install-plugins.sh#L10))

If you have a Dockerfile to provision your Jenkins instance, you can install this plugin manually
from your Dockerfile. Here's a sample Dockerfile for building a Jenkins image from the LTS base image
with some custom CA certificates and the local build of the crowd2 plugin:

```
FROM jenkins/jenkins:lts
USER 0
#Must use root to install the cacerts
COPY ./certs/* /usr/local/share/ca-certificates/my-certs/
RUN update-ca-certificates
USER 1000
COPY ./crowd2/crowd-bot.jpi /usr/share/jenkins/ref/plugins/
```