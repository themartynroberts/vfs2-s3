package org.apache.commons.vfs2.provider.s3.opertations;

import org.apache.commons.vfs2.provider.s3.operations.Acl;
import org.junit.Assert;
import org.junit.Test;

public class AclTest
{

    @Test
    public void testOperations()
    {
        Acl acl = new Acl(null);
        acl.denyAll();

        // Allow single right
        acl.allow(Acl.Group.OWNER, Acl.Permission.WRITE);
        Assert.assertTrue(acl.isAllowed(Acl.Group.OWNER, Acl.Permission.WRITE));

        // Deny single right
        acl.deny(Acl.Group.OWNER, Acl.Permission.WRITE);
        Assert.assertTrue(acl.isDenied(Acl.Group.OWNER, Acl.Permission.WRITE));

        // Allow rights
        Acl.Permission[] rights = {Acl.Permission.READ, Acl.Permission.WRITE};
        acl.allow(Acl.Group.AUTHORIZED, rights);
        Assert.assertTrue(acl.isAllowed(Acl.Group.AUTHORIZED, Acl.Permission.WRITE));
        Assert.assertTrue(acl.isAllowed(Acl.Group.AUTHORIZED, Acl.Permission.READ));

        // Deny rights
        acl.deny(Acl.Group.AUTHORIZED, rights);
        Assert.assertTrue(acl.isDenied(Acl.Group.AUTHORIZED, Acl.Permission.WRITE));
        Assert.assertTrue(acl.isDenied(Acl.Group.AUTHORIZED, Acl.Permission.READ));

        // Allow all to group
        acl.allow(Acl.Group.AUTHORIZED);
        Assert.assertTrue(acl.isAllowed(Acl.Group.AUTHORIZED, Acl.Permission.WRITE));
        Assert.assertTrue(acl.isAllowed(Acl.Group.AUTHORIZED, Acl.Permission.READ));

        // Deny all to group
        acl.deny(Acl.Group.AUTHORIZED);
        Assert.assertTrue(acl.isDenied(Acl.Group.AUTHORIZED, Acl.Permission.WRITE));
        Assert.assertTrue(acl.isDenied(Acl.Group.AUTHORIZED, Acl.Permission.READ));

        // Allow all to all
        acl.allowAll();
        Assert.assertTrue(acl.isAllowed(Acl.Group.AUTHORIZED, Acl.Permission.WRITE));
        Assert.assertTrue(acl.isAllowed(Acl.Group.EVERYONE, Acl.Permission.WRITE));
        Assert.assertTrue(acl.isAllowed(Acl.Group.OWNER, Acl.Permission.WRITE));

        // Deny all to all
        acl.denyAll();
        Assert.assertTrue(acl.isDenied(Acl.Group.AUTHORIZED, Acl.Permission.WRITE));
        Assert.assertTrue(acl.isDenied(Acl.Group.EVERYONE, Acl.Permission.WRITE));
        Assert.assertTrue(acl.isDenied(Acl.Group.OWNER, Acl.Permission.WRITE));
    }
}
