package org.apache.commons.vfs2.provider.s3;

import org.apache.commons.vfs2.FileObject;
import org.apache.commons.vfs2.FileSystemException;
import org.junit.Assert;

import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;

import static java.util.Arrays.sort;

/**
 * A bunch of asserts for checking file operations.
 */
public final class FileAssert
{
    /**
     * Check list of children for file object. Number of children and names should exactly as `children` param.
     */
    public static void assertHasChildren(final FileObject file, final String ... children)
    {
        Assert.assertNotNull("Source file object is null", file);

        FileObject[] siblings = null;

        try {
            siblings = file.getChildren();
        } catch (FileSystemException e) {
            Assert.fail("Not able to get children for " + file);
        }

        sort(children);

        Set<String> names = new TreeSet<String>();

        for (FileObject sibling : siblings) {
            names.add(sibling.getName().getBaseName());
        }

        if (names.size() != children.length) {
            Assert.fail(
                    "Wrong number of children for " + file +
                            ". Expected <" + Arrays.toString(children) +
                            "> but was <" + names.toString() + ">"
            );
        }

        int i = 0;

        for (String name : names) {
            if (!name.equals(children[i++])) {
                Assert.fail(
                        "Wrong list of children for " + file +
                        ". Expected <" + Arrays.toString(children) +
                        "> but was <" + names.toString() + ">"
                );
            }
        }
    }

    private FileAssert() {
    }
}
