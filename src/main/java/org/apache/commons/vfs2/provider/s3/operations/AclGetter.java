package org.apache.commons.vfs2.provider.s3.operations;

import org.apache.commons.vfs2.provider.s3.S3FileObject;
import org.apache.commons.vfs2.provider.s3.operations.Acl;
import org.apache.commons.vfs2.provider.s3.operations.IAclGetter;
import org.apache.commons.vfs2.FileSystemException;

class AclGetter implements IAclGetter {

    private S3FileObject file;

    private Acl acl;

    public AclGetter (S3FileObject file) {
        this.file = file;
    }

    @Override
    public boolean canRead(Acl.Group group) {
        return acl.isAllowed(group, Acl.Permission.READ);
    }

    @Override
    public boolean canWrite(Acl.Group group) {
        return acl.isAllowed(group, Acl.Permission.WRITE);
    }

    @Override
    public Acl getAcl() {
        return acl;
    }

    @Override
    public void process() throws FileSystemException {
        acl = file.getAcl();
    }

}
