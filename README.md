Jenkins Artik Cloud Notifier
============================

This is a Jenkins plugin that sends build status to Artik Cloud.


Usage
-----

Once the plugin is installed, you can configure a device that will receive the build status by default if the post build step is activated in a build.

![Global Settings](/screenshots/JenkinsGlobalConfig.png?raw=true "Global Settings")


When adding the step in a build, you can use the global values as default, or override them

![Job Settings](/screenshots/JenkinsJobConfig.png?raw=true "Job Settings")


You will have to create a device in Artik Cloud using device type "Jenkins Build Notifier"

![Device Creation](/screenshots/ArtikCloudCreateDevice.png?raw=true "Device Creation")


And get the device ID and device token

![Device Informations](/screenshots/ArtikCloudDevice.png?raw=true "Device Information")


The device selected receive information about the build

![Build Informations](/screenshots/ArtikCloudBuildInfo.png?raw=true "Build Information")


Build
-----

To build this plugin : 

    mvn install
