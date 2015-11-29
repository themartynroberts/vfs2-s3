package org.apache.commons.vfs2.provider.s3.operations;

import org.apache.commons.vfs2.provider.s3.S3FileObject;
import org.apache.commons.vfs2.provider.s3.operations.IPublicUrlsGetter;
import org.apache.commons.vfs2.FileSystemException;

/**
 * @author <A href="mailto:alexey at abashev dot ru">Alexey Abashev</A>
 * @version $Id$
 */
class PublicUrlsGetter implements IPublicUrlsGetter {
    private final S3FileObject file;

    public PublicUrlsGetter(S3FileObject file) {
        this.file = file;
    }

    @Override
    public String getHttpUrl() {
        return file.getHttpUrl();
    }

    @Override
    public String getPrivateUrl() {
        try {
            return file.getPrivateUrl();
        } catch (FileSystemException e) {
            throw new IllegalStateException("Not able to get private url", e);
        }
    }

    @Override
    public String getSignedUrl(int expireInSeconds) throws FileSystemException {
        return file.getSignedUrl(expireInSeconds);
    }

    @Override
    public void process() throws FileSystemException {
        // Nothing to do
    }
}
