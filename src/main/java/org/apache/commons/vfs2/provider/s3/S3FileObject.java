package org.apache.commons.vfs2.provider.s3;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.event.ProgressEvent;
import com.amazonaws.event.ProgressEventType;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.Headers;
import com.amazonaws.services.s3.internal.Mimetypes;
import com.amazonaws.services.s3.model.AccessControlList;
import com.amazonaws.services.s3.model.Bucket;
import com.amazonaws.services.s3.model.CanonicalGrantee;
import com.amazonaws.services.s3.model.CopyObjectRequest;
import com.amazonaws.services.s3.model.Grant;
import com.amazonaws.services.s3.model.Grantee;
import com.amazonaws.services.s3.model.GroupGrantee;
import com.amazonaws.services.s3.model.ListObjectsRequest;
import com.amazonaws.services.s3.model.ObjectListing;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.Owner;
import com.amazonaws.services.s3.model.Permission;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectSummary;
import com.amazonaws.services.s3.transfer.PersistableTransfer;
import com.amazonaws.services.s3.transfer.TransferManager;
import com.amazonaws.services.s3.transfer.internal.S3ProgressListener;
import com.amazonaws.util.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.vfs2.FileName;
import org.apache.commons.vfs2.FileObject;
import org.apache.commons.vfs2.FileSelector;
import org.apache.commons.vfs2.FileSystemException;
import org.apache.commons.vfs2.FileType;
import org.apache.commons.vfs2.NameScope;
import org.apache.commons.vfs2.Selectors;
import org.apache.commons.vfs2.provider.AbstractFileName;
import org.apache.commons.vfs2.provider.AbstractFileObject;
import org.apache.commons.vfs2.provider.s3.operations.Acl;
import org.apache.commons.vfs2.provider.s3.operations.IAclGetter;
import org.apache.commons.vfs2.util.MonitorInputStream;
import org.apache.commons.vfs2.util.MonitorOutputStream;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

import static com.amazonaws.services.s3.model.ObjectMetadata.AES_256_SERVER_SIDE_ENCRYPTION;
import static java.util.Calendar.SECOND;
import static org.apache.commons.vfs2.FileName.SEPARATOR;
import static org.apache.commons.vfs2.NameScope.CHILD;
import static org.apache.commons.vfs2.NameScope.FILE_SYSTEM;
import static org.apache.commons.vfs2.provider.s3.AmazonS3ClientHack.extractCredentials;
import static org.apache.commons.vfs2.provider.s3.operations.Acl.Permission.READ;
import static org.apache.commons.vfs2.provider.s3.operations.Acl.Permission.WRITE;

/**
 * Implementation of the virtual S3 file system object using the AWS-SDK.
 */
public class S3FileObject extends AbstractFileObject
{
    private static final Log LOG = LogFactory.getLog(S3FileObject.class);

    private ObjectMetadata objectMetadata;
    private String objectKey;

    /**
     * True when content attached to file
     */
    private boolean attached;

    /**
     * Amazon file owner. Used in ACL
     */
    private Owner fileOwner;

    /**
     * Count down latch to support a blocking exists() call during uploads.
     */
    private CountDownLatch uploading;

    public S3FileObject(final AbstractFileName fileName,
                        final S3FileSystem fileSystem) throws FileSystemException
    {
        super(fileName, fileSystem);
    }

    @Override
    protected synchronized void doAttach()
    {
        if (!attached) {
            try {
                // Do we have file with name?
                String candidateKey = getS3Key();
                objectMetadata = getService().getObjectMetadata(getBucket().getName(), candidateKey);
                objectKey = candidateKey;
                LOG.info("Attach file to S3 Object: " + objectKey);

                attached = true;
                return;
            } catch (AmazonServiceException e) {
                // No, we don't
            }

            try {
                // Do we have folder with that name?
                String candidateKey = getS3Key() + FileName.SEPARATOR;
                objectMetadata = getService().getObjectMetadata(getBucket().getName(), candidateKey);
                objectKey = candidateKey;
                LOG.info("Attach folder to S3 Object: " + objectKey);

                attached = true;
                return;
            } catch (AmazonServiceException e) {
                // No, we don't
            }

            // Create a new
            if (objectMetadata == null) {
                objectMetadata = new ObjectMetadata();
                objectKey = getS3Key();
                objectMetadata.setLastModified(new Date());

                LOG.info("Attach new S3 Object: " + objectKey);

                attached = true;
            }
        }
    }

    @Override
    protected synchronized void doDetach()
    {
        if (attached) {
            LOG.info("Detach from S3 Object: " + objectKey);
            objectMetadata = null;
            attached = false;
        }
    }

    @Override
    protected void doDelete() throws Exception
    {
        getService().deleteObject(getBucket().getName(), objectKey);
    }

    @Override
    protected void doCreateFolder() throws Exception
    {
        if (LOG.isDebugEnabled()) {
            LOG.debug(
                    "Create new folder in bucket [" +
                            ((getBucket() != null) ? getBucket().getName() : "null") +
                            "] with key [" +
                            ((objectMetadata != null) ? objectKey : "null") +
                            "]"
            );
        }

        if (objectMetadata == null) {
            return;
        }

        InputStream input = new ByteArrayInputStream(new byte[0]);
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(0);

        if (getServerSideEncryption()) {
            metadata.setSSEAlgorithm(AES_256_SERVER_SIDE_ENCRYPTION);
        }

        String dirName = objectKey.endsWith(SEPARATOR) ? objectKey : objectKey + SEPARATOR;
        getService().putObject(new PutObjectRequest(getBucket().getName(), dirName, input, metadata));
    }

    @Override
    protected long doGetLastModifiedTime() throws Exception
    {
        return objectMetadata.getLastModified().getTime();
    }

    @Override
    protected boolean doSetLastModifiedTime(final long modtime) throws Exception
    {
        long oldModified = objectMetadata.getLastModified().getTime();
        boolean differentModifiedTime = oldModified != modtime;
        if (differentModifiedTime) {
            objectMetadata.setLastModified(new Date(modtime));
        }
        return differentModifiedTime;
    }

    @Override
    protected InputStream doGetInputStream() throws Exception
    {
        S3Object s3Object = getService().getObject(getBucket().getName(), objectKey);
        return new S3InputStream(s3Object);
    }

    @Override
    protected OutputStream doGetOutputStream(boolean bAppend) throws Exception
    {
        // TODO: get file size of upload prior to performing upload
        return new S3OutputStream(upload(null), uploading);
    }

    @Override
    protected FileType doGetType() throws Exception
    {
        if (objectMetadata.getContentType() == null) {
            return FileType.IMAGINARY;
        }

        if ("".equals(objectKey) || isDirectoryPlaceholder()) {
            return FileType.FOLDER;
        }

        return FileType.FILE;
    }

    @Override
    protected String[] doListChildren() throws Exception
    {
        String path = objectKey;
        // make sure we add a '/' slash at the end to find children
        if ((!"".equals(path)) && (!path.endsWith(SEPARATOR))) {
            path = path + "/";
        }

        final ListObjectsRequest loReq = new ListObjectsRequest();
        loReq.setBucketName(getBucket().getName());
        loReq.setDelimiter("/");
        loReq.setPrefix(path);

        ObjectListing listing = getService().listObjects(loReq);
        final List<S3ObjectSummary> summaries = new ArrayList<S3ObjectSummary>(listing.getObjectSummaries());
        final Set<String> commonPrefixes = new TreeSet<String>(listing.getCommonPrefixes());
        while (listing.isTruncated()) {
            listing = getService().listNextBatchOfObjects(listing);
            summaries.addAll(listing.getObjectSummaries());
            commonPrefixes.addAll(listing.getCommonPrefixes());
        }

        List<String> childrenNames = new ArrayList<String>(summaries.size() + commonPrefixes.size());

        // add the prefixes (non-empty subdirs) first
        for (String commonPrefix : commonPrefixes) {
            // strip path from name (leave only base name)
            final String stripPath = commonPrefix.substring(path.length());
            childrenNames.add(stripPath);
        }

        for (S3ObjectSummary summary : summaries) {
            if (!summary.getKey().equals(path)) {
                // strip path from name (leave only base name)
                final String stripPath = summary.getKey().substring(path.length());
                childrenNames.add(stripPath);
            }
        }

        return childrenNames.toArray(new String[childrenNames.size()]);
    }

    /**
     * Lists the children of this file.  Is only called if {@link #doGetType}
     * returns {@link FileType#FOLDER}.  The return value of this method
     * is cached, so the implementation can be expensive.<br>
     * Other than <code>doListChildren</code> you could return FileObject's to e.g. reinitialize the
     * type of the file.<br>
     * (Introduced for Webdav: "permission denied on resource" during getType())
     * @return The children of this FileObject.
     * @throws Exception if an error occurs.
     */
    @Override
    protected FileObject[] doListChildrenResolved() throws Exception
    {
        String path = objectKey;
        // make sure we add a '/' slash at the end to find children
        if ((!"".equals(path)) && (!path.endsWith(SEPARATOR))) {
            path = path + "/";
        }

        final ListObjectsRequest loReq = new ListObjectsRequest();
        loReq.setBucketName(getBucket().getName());
        loReq.setDelimiter("/");
        loReq.setPrefix(path);

        ObjectListing listing = getService().listObjects(loReq);
        final List<S3ObjectSummary> summaries = new ArrayList<S3ObjectSummary>(listing.getObjectSummaries());
        final Set<String> commonPrefixes = new TreeSet<String>(listing.getCommonPrefixes());
        while (listing.isTruncated()) {
            listing = getService().listNextBatchOfObjects(listing);
            summaries.addAll(listing.getObjectSummaries());
            commonPrefixes.addAll(listing.getCommonPrefixes());
        }

        List<FileObject> resolvedChildren = new ArrayList<FileObject>(summaries.size() + commonPrefixes.size());

        // add the prefixes (non-empty subdirs) first
        for (String commonPrefix : commonPrefixes) {
            // strip path from name (leave only base name)
            String stripPath = commonPrefix.substring(path.length());
            FileObject childObject = resolveFile(stripPath, (stripPath.equals("/")) ? FILE_SYSTEM : CHILD);

            if ((childObject instanceof S3FileObject) && !stripPath.equals("/")) {
                resolvedChildren.add(childObject);
            }
        }

        for (S3ObjectSummary summary : summaries) {
            if (!summary.getKey().equals(path)) {
                // strip path from name (leave only base name)
                final String stripPath = summary.getKey().substring(path.length());
                FileObject childObject = resolveFile(stripPath, CHILD);
                if (childObject instanceof S3FileObject) {
                    S3FileObject s3FileObject = (S3FileObject) childObject;
                    ObjectMetadata childMetadata = new ObjectMetadata();
                    childMetadata.setContentLength(summary.getSize());
                    childMetadata.setContentType(
                            Mimetypes.getInstance().getMimetype(s3FileObject.getName().getBaseName()));
                    childMetadata.setLastModified(summary.getLastModified());
                    childMetadata.setHeader(Headers.ETAG, summary.getETag());
                    s3FileObject.objectMetadata = childMetadata;
                    s3FileObject.objectKey = summary.getKey();
                    s3FileObject.attached = true;
                    resolvedChildren.add(s3FileObject);
                }
            }
        }

        return resolvedChildren.toArray(new FileObject[resolvedChildren.size()]);
    }

    @Override
    protected long doGetContentSize() throws Exception
    {
        return objectMetadata.getContentLength();
    }

    // Utility methods

    private boolean isDirectoryPlaceholder()
    {
        return objectKey.endsWith("/") && objectMetadata.getContentLength() == 0;
    }


    /**
     * Create an S3 key from a commons-vfs path. This simply strips the slash
     * from the beginning if it exists.
     *
     * @return the S3 object key
     */
    private String getS3Key()
    {
        return getS3Key(getName());
    }

    private String getS3Key(final FileName fileName)
    {
        String path = fileName.getPath();

        if ("".equals(path)) {
            return path;
        } else {
            return path.substring(1);
        }
    }

    // ACL extension methods

    /**
     * Returns S3 file owner.
     * Loads it from S3 if needed.
     */
    private Owner getS3Owner()
    {
        if (fileOwner == null) {
            AccessControlList s3Acl = getS3Acl();
            fileOwner = s3Acl.getOwner();
        }
        return fileOwner;
    }

    /**
     * Get S3 ACL list
     * @return acl list
     */
    private AccessControlList getS3Acl()
    {
        String key = getS3Key();
        return "".equals(key) ? getService().getBucketAcl(getBucket().getName()) : getService().getObjectAcl(getBucket().getName(), key);
    }

    /**
     * Put S3 ACL list
     * @param s3Acl acl list
     */
    private void putS3Acl(final AccessControlList s3Acl)
    {
        String key = getS3Key();
        // Determine context. Object or Bucket
        if ("".equals(key)) {
            getService().setBucketAcl(getBucket().getName(), s3Acl);
        } else {
            // Before any operations with object it must be attached
            doAttach();
            // Put ACL to S3
            getService().setObjectAcl(getBucket().getName(), objectKey, s3Acl);
        }
    }

    /**
     * Returns access control list for this file.
     *
     * VFS interfaces doesn't provide interface to manage permissions. ACL can be accessed through {@link FileObject#getFileOperations()}
     * Sample: <code>file.getFileOperations().getOperation(IAclGetter.class)</code>
     * @see {@link FileObject#getFileOperations()}
     * @see {@link IAclGetter}
     *
     * @return Current Access control list for a file
     * @throws FileSystemException
     */
    public Acl getAcl () throws FileSystemException
    {
        Acl myAcl = new Acl();
        AccessControlList s3Acl;
        try {
            s3Acl = getS3Acl();
        } catch (AmazonServiceException e) {
            throw new FileSystemException(e);
        }

        // Get S3 file owner
        Owner owner = s3Acl.getOwner();
        fileOwner = owner;

        // Read S3 ACL list and build VFS ACL.
        Set<Grant> grants = s3Acl.getGrants();

        for (Grant item : grants) {
            // Map enums to jets3t ones
            Permission perm = item.getPermission();
            Acl.Permission[] rights;
            if (perm.equals(Permission.FullControl)) {
                rights = Acl.Permission.values();
            } else if (perm.equals(Permission.Read)) {
                rights = new Acl.Permission[1];
                rights[0] = READ;
            } else if (perm.equals(Permission.Write)) {
                rights = new Acl.Permission[1];
                rights[0] = WRITE;
            } else {
                // Skip unknown permission
                LOG.error(String.format("Skip unknown permission %s", perm));
                continue;
            }

            // Set permissions for groups
            if (item.getGrantee() instanceof GroupGrantee) {
                GroupGrantee grantee = (GroupGrantee)item.getGrantee();
                if (GroupGrantee.AllUsers.equals(grantee)) {
                    // Allow rights to GUEST
                    myAcl.allow(Acl.Group.EVERYONE, rights);
                } else if (GroupGrantee.AuthenticatedUsers.equals(grantee)) {
                    // Allow rights to AUTHORIZED
                    myAcl.allow(Acl.Group.AUTHORIZED, rights);
                }
            } else if (item.getGrantee() instanceof CanonicalGrantee) {
                CanonicalGrantee grantee = (CanonicalGrantee)item.getGrantee();
                if (grantee.getIdentifier().equals(owner.getId())) {
                    // The same owner and grantee understood as OWNER group
                    myAcl.allow(Acl.Group.OWNER, rights);
                }
            }

        }

        return myAcl;
    }

    /**
     * Returns access control list for this file.
     *
     * VFS interfaces doesn't provide interface to manage permissions. ACL can be accessed through {@link FileObject#getFileOperations()}
     * Sample: <code>file.getFileOperations().getOperation(IAclGetter.class)</code>
     * @see {@link FileObject#getFileOperations()}
     * @see {@link IAclGetter}
     *
     * @param acl the access control list
     * @throws FileSystemException
     */
    public void setAcl(final Acl acl) throws FileSystemException
    {

        // Create empty S3 ACL list
        AccessControlList s3Acl = new AccessControlList();

        // Get file owner
        Owner owner;
        try {
            owner = getS3Owner();
        } catch (AmazonServiceException e) {
            throw new FileSystemException(e);
        }
        s3Acl.setOwner(owner);

        // Iterate over VFS ACL rules and fill S3 ACL list
        Map<Acl.Group, Acl.Permission[]> rules = acl.getRules();

        final Acl.Permission[] allRights = Acl.Permission.values();

        for (Acl.Group group : rules.keySet()) {
            Acl.Permission[] rights = rules.get(group);

            if (rights.length == 0) {
                // Skip empty rights
                continue;
            }

            // Set permission
            Permission perm;
            if (Arrays.equals(rights, allRights)) {
                perm = Permission.FullControl;
            } else if (acl.isAllowed(group, READ)) {
                perm = Permission.Read;
            } else if (acl.isAllowed(group, WRITE)) {
                perm = Permission.Write;
            } else {
                LOG.error(String.format("Skip unknown set of rights %s", Arrays.toString(rights)));
                continue;
            }

            // Set grantee
            Grantee grantee;
            if (group.equals(Acl.Group.EVERYONE)) {
                grantee = GroupGrantee.AllUsers;
            } else if (group.equals(Acl.Group.AUTHORIZED)) {
                grantee = GroupGrantee.AuthenticatedUsers;
            } else if (group.equals(Acl.Group.OWNER)) {
                grantee = new CanonicalGrantee(owner.getId());
            } else {
                LOG.error(String.format("Skip unknown group %s", group));
                continue;
            }

            // Grant permission
            s3Acl.grantPermission(grantee, perm);
        }

        // Put ACL to S3
        try {
            putS3Acl(s3Acl);
        } catch (Exception e) {
            throw new FileSystemException(e);
        }
    }

    /**
     * Get direct http url to S3 object.
     * @return the direct http url to S3 object
     */
    public String getHttpUrl()
    {
        StringBuilder sb = new StringBuilder("http://" + getBucket().getName() + ".s3.amazonaws.com/");
        String key = getS3Key();

        // Determine context. Object or Bucket
        if ("".equals(key)) {
            return sb.toString();
        } else {
            return sb.append(key).toString();
        }
    }

    /**
     * Get private url with access key and secret key.
     *
     * @return the private url
     */
    public String getPrivateUrl() throws FileSystemException
    {
        AWSCredentials awsCredentials = S3FileSystemConfigBuilder.getInstance().getAWSCredentials(getFileSystem().getFileSystemOptions());

        if (awsCredentials == null) {
            awsCredentials = extractCredentials(getService());
        }

        if (awsCredentials == null) {
            throw new FileSystemException("Not able to build private URL - empty AWS credentials");
        }

        return String.format(
                "s3://%s:%s@%s/%s",
                awsCredentials.getAWSAccessKeyId(),
                awsCredentials.getAWSSecretKey(),
                getBucket().getName(),
                getS3Key()
        );
    }

    /**
     * Temporary accessible url for object.
     * @param expireInSeconds seconds until expiration
     * @return temporary accessible url for object
     */
    public String getSignedUrl(final int expireInSeconds) throws FileSystemException
    {
        final Calendar cal = Calendar.getInstance();
        cal.add(SECOND, expireInSeconds);

        try {
            return getService().generatePresignedUrl(getBucket().getName(), getS3Key(), cal.getTime()).toString();
        } catch (AmazonServiceException e) {
            throw new FileSystemException(e);
        }
    }

    /**
     * Get MD5 hash for the file
     * @return md5 hash for file
     */
    public String getMD5Hash() throws FileSystemException
    {
        ObjectMetadata metadata = getObjectMetadata();
        if (metadata != null) {
            return metadata.getETag(); // TODO this is something different than mentioned in methodname / javadoc
        }

        return null;
    }

    public ObjectMetadata getObjectMetadata() throws FileSystemException {
        try {
            return getService().getObjectMetadata(getBucket().getName(), getS3Key());
        } catch (AmazonServiceException e) {
            throw new FileSystemException(e);
        }
    }

    protected AmazonS3 getService()
    {
        return ((S3FileSystem) getFileSystem()).getService();
    }

    protected Bucket getBucket()
    {
        return ((S3FileSystem) getFileSystem()).getBucket();
    }

    @Override
    public boolean canRenameTo(final FileObject newfile)
    {
        return false;
    }

    /**
     * Copies another file to this file.
     * @param file The FileObject to copy.
     * @param selector The FileSelector.
     */
    @Override
    public void copyFrom(final FileObject file, final FileSelector selector) throws FileSystemException
    {
        if (!file.exists()) {
            throw new FileSystemException("vfs.provider/copy-missing-file.error", file);
        }

        // Locate the files to copy across
        final ArrayList<FileObject> files = new ArrayList<FileObject>();
        file.findFiles(selector, false, files);

        // Copy everything across
        for (final FileObject srcFile : files) {
            // Determine the destination file
            final String relPath = file.getName().getRelativeName(srcFile.getName());
            final S3FileObject destFile = (S3FileObject) resolveFile(relPath, NameScope.DESCENDENT_OR_SELF);

            // Clean up the destination file, if necessary
            if (destFile.exists()) {
                if (destFile.getType() != srcFile.getType()) {
                    // The destination file exists, and is not of the same type,
                    // so delete it
                    // TODO - add a pluggable policy for deleting and overwriting existing files
                    destFile.delete(Selectors.SELECT_ALL);
                }
            } else {
                FileObject parent = getParent();
                if (parent != null) {
                    parent.createFolder();
                }
            }

            // Copy across
            try {
                if (srcFile.getType().hasChildren()) {
                    destFile.createFolder();
                    // do server side copy if both source and dest are in S3 and using same credentials
                } else if (srcFile instanceof S3FileObject) {
                    S3FileObject s3SrcFile = (S3FileObject)srcFile;
                    String srcBucketName = s3SrcFile.getBucket().getName();
                    String srcFileName = s3SrcFile.getS3Key();
                    String destBucketName = destFile.getBucket().getName();
                    String destFileName = destFile.getS3Key();
                    CopyObjectRequest copy = new CopyObjectRequest(
                            srcBucketName, srcFileName, destBucketName, destFileName);
                    if (srcFile.getType() == FileType.FILE && getServerSideEncryption()) {
                        ObjectMetadata meta = s3SrcFile.getObjectMetadata();
                        meta.setSSEAlgorithm(AES_256_SERVER_SIDE_ENCRYPTION);
                        copy.setNewObjectMetadata(meta);
                    }
                    getService().copyObject(copy);
                } else if (srcFile.getType().hasContent() && srcFile.getURL().getProtocol().equals("file")) {
                    try {
                        File localFile = new File(srcFile.getURL().toURI());
                        OutputStream os = destFile.upload(localFile.length());
                        InputStream is = new FileInputStream(localFile);
                        IOUtils.copy(is, os);
                        exists();
                    } catch (URISyntaxException e) {
                        // couldn't convert URL to URI, but should still be able to do the slower way
                        super.copyFrom(file, selector);
                    }
                } else {
                    super.copyFrom(file, selector);
                }
            } catch (IOException e) {
                throw new FileSystemException("vfs.provider/copy-file.error", new Object[] { srcFile, destFile }, e);
            } finally {
                destFile.close();
            }
        }
    }

    /**
     * Creates an executor service for use with a TransferManager. This allows us to control the maximum number
     * of threads used because for the TransferManager default of 10 is way too many.
     *
     * @return an executor service
     */
    private ExecutorService createTransferManagerExecutorService()
    {
        int maxThreads = S3FileSystemConfigBuilder.getInstance().getMaxUploadThreads(getFileSystem().getFileSystemOptions());
        ThreadFactory threadFactory = new ThreadFactory() {
            private int threadCount = 1;

            public Thread newThread(Runnable r) {
                Thread thread = new Thread(r);
                thread.setName("s3-upload-" + getName().getBaseName() + "-" + threadCount++);
                return thread;
            }
        };
        return Executors.newFixedThreadPool(maxThreads, threadFactory);
    }

    /**
     * Uploads File to S3
     *
     * @param size the Size of the data upload
     */
    private OutputStream upload(Long size) throws IOException
    {
        uploading = new CountDownLatch(1);

        ObjectMetadata md = new ObjectMetadata();

        if (size != null) {
            md.setContentLength(size);
        }

        md.setContentType(Mimetypes.getInstance().getMimetype(getName().getBaseName()));
        // set encryption if needed
        if (getServerSideEncryption()) {
            md.setSSEAlgorithm(AES_256_SERVER_SIDE_ENCRYPTION);
        }

        PipedInputStream pin = new PipedInputStream();
        PipedOutputStream pout = new PipedOutputStream(pin);

        final PutObjectRequest request = new PutObjectRequest(getBucket().getName(), getS3Key(), pin, md);

        final TransferManager transferManager = new TransferManager(getService(), createTransferManagerExecutorService());
        transferManager.upload(request, new S3ProgressListener() {
            @Override
            public void onPersistableTransfer(PersistableTransfer persistableTransfer) {
                // empty
            }
            @Override
            public void progressChanged(ProgressEvent progressEvent) {
                if (progressEvent.getEventType() == ProgressEventType.TRANSFER_COMPLETED_EVENT
                        || progressEvent.getEventType() == ProgressEventType.TRANSFER_FAILED_EVENT) {
                    transferManager.shutdownNow(false);
                    doDetach();
                    doAttach();
                    uploading.countDown();
                }
            }
        });
        return pout;
    }

    private boolean getServerSideEncryption()
    {
        return S3FileSystemConfigBuilder.getInstance().getServerSideEncryption(getFileSystem().getFileSystemOptions());
    }

    @Override
    public boolean exists() throws FileSystemException
    {
        try {
            if (uploading != null) {
                uploading.await();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return super.exists();
    }

    static class S3OutputStream extends MonitorOutputStream
    {
        private final CountDownLatch uploading;

        public S3OutputStream(final OutputStream out, final CountDownLatch uploading) {
            super(out);
            this.uploading = uploading;
        }

        @Override
        protected void onClose() throws IOException {
//            uploading.countDown();
        }
    }

    static class S3InputStream extends MonitorInputStream
    {
        private final S3Object s3Object;

        public S3InputStream(final S3Object s3Object) throws IOException {
            super(s3Object.getObjectContent());
            this.s3Object = s3Object;
        }

        /**
         * Called after the stream has been closed.
         */
        @Override
        protected void onClose() throws IOException {
            s3Object.close();
        }
    }
}