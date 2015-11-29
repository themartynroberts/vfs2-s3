package org.apache.commons.vfs2.provider.s3;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.Bucket;
import com.amazonaws.services.s3.model.Region;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.vfs2.Capability;
import org.apache.commons.vfs2.FileObject;
import org.apache.commons.vfs2.FileSystemException;
import org.apache.commons.vfs2.FileSystemOptions;
import org.apache.commons.vfs2.provider.AbstractFileName;
import org.apache.commons.vfs2.provider.AbstractFileSystem;

import java.util.Collection;

/**
 * An S3 file system.
 */
public class S3FileSystem extends AbstractFileSystem
{
    private static final Log LOG = LogFactory.getLog(S3FileSystem.class);

    private final AmazonS3Client service;
    private final Bucket bucket;

    private boolean shutdownServiceOnClose = false;

    public S3FileSystem(final S3FileName fileName,
                        final AmazonS3Client service,
                        final FileSystemOptions fileSystemOptions)
            throws FileSystemException
    {
        super(fileName, null, fileSystemOptions);
        this.service = service;

        try
        {
            String bucketName = fileName.getBucketName();
            if (service.doesBucketExist(bucketName))
            {
                bucket = new Bucket(bucketName);
            }
            else
            {
                // TODO: don't perform a function that can fail in the ctor
                // TODO: this may not be desirable, should this be configurable or treated like a directory?
                bucket = service.createBucket(bucketName);
                LOG.debug("S3 Bucket created: " + bucketName);
            }
        }
        catch (AmazonServiceException e)
        {
            throw new FileSystemException(e);
        }
    }

    @Override
    protected void addCapabilities(final Collection<Capability> caps)
    {
        caps.addAll(S3FileProvider.capabilities);
    }

    protected Bucket getBucket()
    {
        return bucket;
    }

    protected Region getRegion()
    {
        return S3FileSystemConfigBuilder.getInstance().getRegion(getFileSystemOptions());
    }

    protected AmazonS3 getService()
    {
        return service;
    }

    @Override
    protected FileObject createFile(final AbstractFileName fileName)
            throws Exception
    {
        return new S3FileObject(fileName, this);
    }

    @Override
    protected void doCloseCommunicationLink()
    {
        if (shutdownServiceOnClose)
        {
            service.shutdown();
        }
    }

    public void setShutdownServiceOnClose(final boolean shutdownServiceOnClose)
    {
        this.shutdownServiceOnClose = shutdownServiceOnClose;
    }
}
