package org.apache.commons.vfs2.provider.s3.operations;


import org.apache.commons.vfs2.provider.s3.S3FileObject;
import org.apache.commons.vfs2.provider.s3.operations.Acl;
import org.apache.commons.vfs2.provider.s3.operations.IAclSetter;
import org.apache.commons.vfs2.FileSystemException;

class AclSetter implements IAclSetter {

    private S3FileObject file;

    private Acl acl;

    public AclSetter(S3FileObject file) {
        this.file = file;
    }

    @Override
    public void setAcl(Acl acl) {
        this.acl = acl;
    }

    @Override
    public void process() throws FileSystemException {
        file.setAcl(acl);
    }
}
