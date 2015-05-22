package com.vleue.sami;

import hudson.Extension;
import hudson.Launcher;
import hudson.ProxyConfiguration;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.tasks.*;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.ProxyAuthenticationStrategy;
import javax.servlet.ServletException;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.SocketAddress;
import java.net.URL;

import org.apache.http.util.EntityUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.QueryParameter;


public class SamiNotifier extends Notifier {

    // attributes --------------------------------------------------------------

    /** base url of SAMI API server, e. g. <tt>https://api.samsunssami.io/v1.1</tt>. */
    private final String samiRootUrl;

    /** Device Token on SAMI. */
    private final String deviceToken;

    /** Device ID on SAMI */
    private final String deviceID;

    private final String STATE_STARTING = "STARTING";
    private final String STATE_UNKNOWN = "UNKNOWN";

    // public members ----------------------------------------------------------

    public BuildStepMonitor getRequiredMonitorService() {
        return BuildStepMonitor.NONE;
    }

    @DataBoundConstructor
    public SamiNotifier(String samiRootUrl, String deviceToken, String deviceID) {
        this.samiRootUrl = samiRootUrl;
        this.deviceToken = deviceToken;
        this.deviceID = deviceID;
    }

    public String getSamiRootUrl() {
        return samiRootUrl;
    }

    public String getDeviceToken() {
        return deviceToken;
    }

    public String getDeviceID() {
        return deviceID;
    }

    @Override
    public boolean prebuild(AbstractBuild<?, ?> build, BuildListener listener) {
        return processJenkinsEvent(build, listener, STATE_STARTING);
    }

    @Override
    public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) {
        if (build.getResult() == null) {
            return processJenkinsEvent(build, listener, STATE_UNKNOWN);
        } else {
            return processJenkinsEvent(build, listener, build.getResult().toString());
        }
    }

    /**
     * Processes the Jenkins events triggered before and after the build and
     * initiates the Sami notification.
     *
     * @param build		the build to notify Sami of
     * @param listener	the Jenkins build listener
     * @param state		the state of the build (in progress, success, failed)
     * @return			always true in order not to abort the Job in case of
     * 					notification failures
     */
    private boolean processJenkinsEvent(final AbstractBuild<?, ?> build, final BuildListener listener, final String state) {

        PrintStream logger = listener.getLogger();

        try {
            notifySami(build, state, logger);
        } catch (Exception e) {
            logger.println("Caught exception while notifying SAMI");
            e.printStackTrace(logger);
        }
        return true;
    }

    /**
     * Returns the HttpClient through which the REST call is made. Uses an
     * unsafe TrustStrategy in case the user specified a HTTPS URL and
     * set the ignoreUnverifiedSSLPeer flag.
     *
     * @return			the HttpClient
     */
    private HttpClient getHttpClient() throws Exception {
        String samiServer = this.samiRootUrl;
        DescriptorImpl descriptor = getDescriptor();
        if ("".equals(samiServer) || samiServer == null) {
            samiServer = descriptor.getSamiRootUrl();
        }

        URL url = new URL(samiServer);
        HttpClientBuilder builder = HttpClientBuilder.create();

        // Configure the proxy, if needed
        // Using the Jenkins methods handles the noProxyHost settings
        ProxyConfiguration proxyConfig = Jenkins.getInstance().proxy;
        if (proxyConfig != null) {
            Proxy proxy = proxyConfig.createProxy(url.getHost());
            if (proxy != null && proxy.type() == Proxy.Type.HTTP) {
                SocketAddress addr = proxy.address();
                if (addr != null && addr instanceof InetSocketAddress) {
                    InetSocketAddress proxyAddr = (InetSocketAddress) addr;
                    HttpHost proxyHost = new HttpHost(proxyAddr.getAddress().getHostAddress(), proxyAddr.getPort());
                    builder = builder.setProxy(proxyHost);

                    String proxyUser = proxyConfig.getUserName();
                    if (proxyUser != null) {
                        String proxyPass = proxyConfig.getPassword();
                        CredentialsProvider cred = new BasicCredentialsProvider();
                        cred.setCredentials(new AuthScope(proxyHost),
                                new UsernamePasswordCredentials(proxyUser, proxyPass));
                        builder = builder
                                .setDefaultCredentialsProvider(cred)
                                .setProxyAuthenticationStrategy(new ProxyAuthenticationStrategy());
                    }
                }
            }
        }

        return builder.build();
    }

    /**
     * Hudson defines a method {@link Builder#getDescriptor()}, which
     * returns the corresponding Descriptor object.
     *
     * Since we know that it's actually {@link DescriptorImpl}, override
     * the method and give a better return type, so that we can access
     * {@link DescriptorImpl} methods more easily.
     *
     * This is not necessary, but just a coding style preference.
     */
    @Override
    public DescriptorImpl getDescriptor() {
        // see Descriptor javadoc for more about what a descriptor is.
        return (DescriptorImpl)super.getDescriptor();
    }

    @Extension
    public static final class DescriptorImpl
            extends BuildStepDescriptor<Publisher> {

        /**
         * To persist global configuration information,
         * simply store it in a field and call save().
         *
         * <p>
         * If you don't want fields to be persisted, use <tt>transient</tt>.
         */

        private String deviceToken;
        private String deviceID;
        private String samiRootUrl;

        public DescriptorImpl() {
            load();
        }

        public String getDeviceToken() {
            if ((deviceToken != null) && (deviceToken.trim().equals(""))) {
                return null;
            } else {
                return deviceToken;
            }
        }

        public String getDeviceID() {
            if ((deviceID != null) && (deviceID.trim().equals(""))) {
                return null;
            } else {
                return deviceID;
            }
        }

        public String getSamiRootUrl() {
            if ((samiRootUrl == null) || (samiRootUrl.trim().equals(""))) {
                return "https://api.samsungsami.io/v1.1";
            } else {
                return samiRootUrl;
            }
        }

        public FormValidation doCheckSamiServerBaseUrl(@QueryParameter String value)
                throws IOException, ServletException {

            // calculate effective url from global and local config
            String url = value;
            if ((url != null) && (!url.trim().equals(""))) {
                url = url.trim();
            } else {
                url = samiRootUrl != null ? samiRootUrl.trim() : null;
            }

            if ((url == null) || url.equals("")) {
                return FormValidation.error(
                        "Please specify a valid URL here or in the global "
                                + "configuration");
            } else {
                try {
                    new URL(url);
                    return FormValidation.ok();
                } catch (Exception e) {
                    return FormValidation.error(
                            "Please specify a valid URL here or in the global "
                                    + "configuration!");
                }
            }
        }

        public FormValidation doCheckDeviceToken(@QueryParameter String value)
                throws IOException, ServletException {

            if (value.trim().equals("")
                    && ((deviceToken == null) || deviceToken.trim().equals(""))) {
                return FormValidation.error(
                        "Please specify a device token here or in the global "
                                + "configuration!");
            } else {
                return FormValidation.ok();
            }
        }

        public FormValidation doCheckDeviceID(@QueryParameter String value)
                throws IOException, ServletException {

            if (value.trim().equals("")
                    && ((deviceID == null) || deviceID.trim().equals(""))) {
                return FormValidation.error(
                        "Please specify a device ID here or in the global "
                                + "configuration!");
            } else {
                return FormValidation.ok();
            }
        }

        @SuppressWarnings("rawtypes")
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        public String getDisplayName() {
            return "Notify SAMI";
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {

            // to persist global configuration information,
            // set that to properties and call save().
            deviceToken = formData.getString("deviceToken");
            deviceID = formData.getString("deviceID");
            samiRootUrl = formData.getString("samiRootUrl");
            save();
            return super.configure(req,formData);
        }
    }

    // non-public members ------------------------------------------------------

    /**
     * Notifies the configured SAMI server by POSTing the build results
     * to the SAMI message API.
     *
     * @param build			the build to notify SAMI of
     * @param state			the state of the build as defined by the SAMI API.
     * @param logger		the logger to use
     */
    private void notifySami(
            final AbstractBuild<?, ?> build,
            final String state,
            final PrintStream logger
            ) throws Exception {
        HttpEntity samiBuildNotificationEntity = newSamiBuildNotificationEntity(build, state);
        HttpPost req = createRequest(samiBuildNotificationEntity);
        HttpClient client = getHttpClient();
        try {
            HttpResponse res = client.execute(req);
            if (res.getStatusLine().getStatusCode() == 200) {
                logger.println("Notified SAMI : " + state);
            } else {
                HttpEntity entity = res.getEntity();
                String responseString = EntityUtils.toString(entity, "UTF-8");
                logger.println("Failed to notify SAMI : " + responseString);
            }
        } finally {
            client.getConnectionManager().shutdown();
        }
    }

    /**
     * Returns the HTTP POST request ready to be sent to the SAMI message API for
     * the given build and change set.
     *
     * @param samiBuildNotificationEntity	a entity containing the parameters
     * 										for SAMI
     * @return				the HTTP POST request to the SAMI build API
     */
    private HttpPost createRequest(
            final HttpEntity samiBuildNotificationEntity) {

        String url = this.samiRootUrl;
        String deviceToken = this.deviceToken;
        DescriptorImpl descriptor = getDescriptor();

        if ("".equals(url) || url == null)
            url = descriptor.getSamiRootUrl();
        if ("".equals(deviceToken) || deviceToken == null)
            deviceToken = descriptor.getDeviceToken();

        HttpPost req = new HttpPost(url + "/messages");

        req.addHeader("Content-Type", "application/json");
        req.addHeader("Authorization", "bearer " + deviceToken);
        req.setEntity(samiBuildNotificationEntity);

        return req;
    }

    /**
     * Returns the HTTP POST entity body with the JSON representation of the
     * builds result to be sent to the SAMI build API.
     *
     * @param build			the build to notify SAMI of
     * @param state         the state of the build
     * @return				HTTP entity body for POST to SAMI build API
     */
    private HttpEntity newSamiBuildNotificationEntity(
            final AbstractBuild<?, ?> build,
            final String state) throws UnsupportedEncodingException {
        String deviceID = this.deviceID;
        DescriptorImpl descriptor = getDescriptor();

        if ("".equals(deviceID) || deviceID == null)
            deviceID = descriptor.getDeviceID();

        JSONObject data = new JSONObject();
        data.put("state", state);
        if (!state.equals(STATE_STARTING)) {
            data.put("duration", System.currentTimeMillis() - build.getStartTimeInMillis());
        }
        data.put("name", build.getProject().getName());
        data.put("number", build.getNumber());

        JSONObject json = new JSONObject();
        json.put("sdid", deviceID);
        json.put("type", "message");
        json.put("data", data);

        return new StringEntity(json.toString(), "UTF-8");
    }
}
