package org.apache.commons.vfs2.provider.s3;

import org.apache.commons.vfs2.FileSystemOptions;
import org.apache.commons.vfs2.auth.StaticUserAuthenticator;
import org.apache.commons.vfs2.impl.DefaultFileSystemConfigBuilder;
import org.junit.Assert;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class TestEnvironment
{
    public static final String ACCESS_KEY = "aws.accessKey";
    public static final String SECRET_KEY = "aws.secretKey";

    private static TestEnvironment instance;
    static {
        try {
            instance = new TestEnvironment();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static TestEnvironment getInstance ()
    {
        return instance;
    }

    private Properties config;

    private TestEnvironment() throws IOException
    {
        // Load configuration
        config = new Properties();

        InputStream configFile = TestEnvironment.class.getResourceAsStream("/config.properties");
        Assert.assertNotNull(configFile);
        config.load(configFile);

        // Override with system settings if they exist
        for (String key : config.stringPropertyNames()) {
            config.setProperty(key, getSetting(key));
        }

        // Configure VFS
        StaticUserAuthenticator auth = new StaticUserAuthenticator(null, config.getProperty(ACCESS_KEY), config.getProperty(SECRET_KEY));
        FileSystemOptions opts = S3FileProvider.getDefaultFileSystemOptions();
        DefaultFileSystemConfigBuilder.getInstance().setUserAuthenticator(opts, auth);
    }

    public Properties getConfig () {
        return config;
    }

    private String getSetting(String key)
    {
        String override = System.getProperty(key);
        if (override != null) {
            return override;
        }
        return (String) config.get(key);
    }
}
