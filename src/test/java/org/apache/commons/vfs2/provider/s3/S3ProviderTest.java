package org.apache.commons.vfs2.provider.s3;

import com.amazonaws.services.s3.model.Region;
import com.amazonaws.services.s3.transfer.TransferManagerConfiguration;
import org.apache.commons.io.IOUtils;
import org.apache.commons.vfs2.FileObject;
import org.apache.commons.vfs2.FileSystemException;
import org.apache.commons.vfs2.FileSystemManager;
import org.apache.commons.vfs2.FileSystemOptions;
import org.apache.commons.vfs2.FileType;
import org.apache.commons.vfs2.Selectors;
import org.apache.commons.vfs2.VFS;
import org.apache.commons.vfs2.provider.AbstractFileSystem;
import org.apache.commons.vfs2.provider.s3.operations.IMD5HashGetter;
import org.apache.commons.vfs2.provider.s3.operations.IPublicUrlsGetter;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Locale;
import java.util.Properties;
import java.util.Random;

import static com.amazonaws.services.s3.model.ObjectMetadata.AES_256_SERVER_SIDE_ENCRYPTION;
import static org.apache.commons.vfs2.Selectors.SELECT_ALL;
import static org.apache.commons.vfs2.provider.s3.FileAssert.assertHasChildren;
import static org.junit.Assert.*;

public class S3ProviderTest
{
    private static final String BACKUP_ZIP = "src/test/resources/backup.zip";
    private static final String BIG_FILE = "big_file.iso";

    private FileSystemManager fsManager;
    private String fileName, encryptedFileName, dirName, bucketName, bigFile;
    private FileObject file, dir;
    private int bigFileMaxThreads;

    @Before
    public void setUp() throws IOException
    {
        Properties config = TestEnvironment.getInstance().getConfig();

        fsManager = VFS.getManager();
        Random r = new Random();
        encryptedFileName = "vfs-encrypted-file" + r.nextInt(1000);
        fileName = "vfs-file" + r.nextInt(1000);
        dirName = "vfs-dir" + r.nextInt(1000);
        bucketName = config.getProperty("s3.testBucket", "vfs-s3-tests");
        bigFile = config.getProperty("big.file");
        bigFileMaxThreads = Integer.parseInt(config.getProperty("big.file.maxThreads", "2"));

        file = fsManager.resolveFile("s3://" + bucketName + "/test-place/" + fileName);
        file.createFile();
        assertTrue(file.exists());
    }

    @Test
    public void setRegion() throws FileSystemException
    {
        FileSystemOptions regionOpts = (FileSystemOptions) S3FileProvider.getDefaultFileSystemOptions().clone();

        S3FileSystemConfigBuilder.getInstance().setRegion(regionOpts, Region.US_West_2);

        FileObject regFile = fsManager.resolveFile("s3://" + bucketName + "/test-place/" + fileName, regionOpts);

        assertEquals(Region.US_West_2, ((S3FileSystem) regFile.getFileSystem()).getRegion());
    }


    @Test
    public void defaultRegion()
    {
        assertEquals(Region.US_Standard, ((S3FileSystem) file.getFileSystem()).getRegion());
    }

    @Test
    public void createEncryptedFileOk() throws FileSystemException
    {
        final FileSystemOptions options = (FileSystemOptions) S3FileProvider.getDefaultFileSystemOptions().clone();

        S3FileSystemConfigBuilder.getInstance().setServerSideEncryption(options, true);

        file = fsManager.resolveFile("s3://" + bucketName + "/test-place/" + encryptedFileName, options);

        file.createFile();

        assertTrue(file.exists());
        assertEquals(AES_256_SERVER_SIDE_ENCRYPTION, ((S3FileObject) file).getObjectMetadata().getSSEAlgorithm());
    }

    @Test(expected=FileSystemException.class)
    public void createFileFailed() throws FileSystemException
    {
        FileObject tmpFile = fsManager.resolveFile("s3://../new-mpoint/vfs-bad-file");
        tmpFile.createFile();
    }

    /**
     * Create folder on already existed file
     */
    @Test(expected=FileSystemException.class)
    public void createFileFailed2() throws FileSystemException
    {
        FileObject tmpFile = fsManager.resolveFile("s3://" + bucketName + "/test-place/" + fileName);
        tmpFile.createFolder();
    }

    @Test
    public void createDirOk() throws FileSystemException
    {
        dir = fsManager.resolveFile("s3://" + bucketName + "/test-place/" + dirName);
        dir.createFolder();
        assertTrue(dir.exists());
    }

    @Test(expected = FileSystemException.class)
    public void createDirFailed() throws FileSystemException
    {
        FileObject tmpFile = fsManager.resolveFile("s3://../new-mpoint/vfs-bad-dir");
        tmpFile.createFolder();
    }

    /**
     * Create file on already existed folder
     */
    @Test(expected = FileSystemException.class)
    public void createDirFailed2() throws FileSystemException
    {
        createDirOk();

        FileObject tmpFile = fsManager.resolveFile("s3://" + bucketName + "/test-place/" + dirName);
        tmpFile.createFile();
    }

    @Test
    public void exists() throws IOException
    {
        upload();

        // Existed dir
        FileObject existedDir = fsManager.resolveFile("s3://" + bucketName + "/test-place");
        assertTrue(existedDir.exists());

        // Non-existed dir
        FileObject nonExistedDir = fsManager.resolveFile(existedDir, "path/to/non/existed/dir");
        assertFalse(nonExistedDir.exists());

        // Existed file
        FileObject existedFile = fsManager.resolveFile("s3://" + bucketName + "/test-place/backup.zip");
        assertTrue(existedFile.exists());

        // Non-existed file
        FileObject nonExistedFile = fsManager.resolveFile("s3://" + bucketName + "/ne/bыlo/i/net");
        assertFalse(nonExistedFile.exists());
    }

    @Test
    public void upload() throws IOException
    {
        FileObject dest = fsManager.resolveFile("s3://" + bucketName + "/test-place/backup.zip");

        // Delete file if exists
        if (dest.exists()) {
            dest.delete();
        }

        // Copy data
        final File backupFile = new File(BACKUP_ZIP);

        assertTrue("Backup file should exists", backupFile.exists());

        FileObject src = fsManager.resolveFile(backupFile.getAbsolutePath());
        dest.copyFrom(src, Selectors.SELECT_SELF);

        assertTrue(dest.exists() && dest.getType().equals(FileType.FILE));
        assertEquals(null, ((S3FileObject) dest).getObjectMetadata().getSSEAlgorithm());
    }

    @Test
    public void uploadEncrypted() throws IOException
    {
        createEncryptedFileOk();

        final FileSystemOptions options = (FileSystemOptions) S3FileProvider.getDefaultFileSystemOptions().clone();

        S3FileSystemConfigBuilder.getInstance().setServerSideEncryption(options, true);

        FileObject dest = fsManager.resolveFile("s3://" + bucketName + "/test-place/backup.zip", options);

        // Delete file if exists
        if (dest.exists()) {
            dest.delete();
        }

        // Copy data
        final File backupFile = new File(BACKUP_ZIP);

        assertTrue("Backup file should exists", backupFile.exists());

        FileObject src = fsManager.resolveFile(backupFile.getAbsolutePath());
        dest.copyFrom(src, Selectors.SELECT_SELF);

        assertTrue(dest.exists() && dest.getType().equals(FileType.FILE));
        assertEquals(AES_256_SERVER_SIDE_ENCRYPTION, ((S3FileObject)dest).getObjectMetadata().getSSEAlgorithm());
    }

    @Test
    public void uploadMultiple() throws Exception
    {
        FileObject dest = fsManager.resolveFile("s3://" + bucketName + "/test-place/backup.zip");

        // Delete file if exists
        if (dest.exists()) {
            dest.delete();
        }

        // Copy data
        final File backupFile = new File(BACKUP_ZIP);

        assertTrue("Backup file should exists", backupFile.exists());

        FileObject src = fsManager.resolveFile(backupFile.getAbsolutePath());

        // copy twice
        dest.copyFrom(src, Selectors.SELECT_SELF);
        Thread.sleep(2000L);
        dest.copyFrom(src, Selectors.SELECT_SELF);

        assertTrue(dest.exists() && dest.getType().equals(FileType.FILE));
    }

    @Test
    public void uploadBigFile() throws IOException
    {
        FileSystemOptions fso = (FileSystemOptions) S3FileProvider.getDefaultFileSystemOptions().clone();
        S3FileSystemConfigBuilder.getInstance().setMaxUploadThreads(fso, bigFileMaxThreads);

        FileObject dest = fsManager.resolveFile("s3://" + bucketName + "/" + BIG_FILE);

        // Delete file if exists
        if (dest.exists()) {
            dest.delete();
        }

        // Copy data
        final File file = new File(bigFile);

        assertTrue("Big file should exists", file.exists());

        FileObject src = fsManager.resolveFile(file.getAbsolutePath());

        if (src.getContent().getSize() < new TransferManagerConfiguration().getMultipartUploadThreshold()) {
            System.err.println("uploadBigFile() needs a file larger than 16MB in order to be useful");
        }

        dest.copyFrom(src, Selectors.SELECT_SELF);

        assertTrue(dest.exists() && dest.getType().equals(FileType.FILE));
    }

    @Test
    public void outputStream() throws IOException
    {
        FileObject dest = fsManager.resolveFile("s3://" + bucketName + "/test-place/output.txt");

        // Delete file if exists
        if (dest.exists()) {
            dest.delete();
        }

        // Copy data
        OutputStream os = dest.getContent().getOutputStream();
        try {
            os.write(BACKUP_ZIP.getBytes("US-ASCII"));
        } finally {
            os.close();
        }
        assertTrue(dest.exists() && dest.getType().equals(FileType.FILE));
        assertEquals(BACKUP_ZIP.length(), dest.getContent().getSize());
        assertEquals(null, ((S3FileObject) dest).getObjectMetadata().getSSEAlgorithm());
        BufferedReader reader = new BufferedReader(new InputStreamReader(dest.getContent().getInputStream(), "US-ASCII"));
        try {
            assertEquals(reader.readLine(), BACKUP_ZIP);
        } finally {
            reader.close();
        }
        dest.delete();
    }

    @Test
    public void outputStreamEncrypted() throws IOException
    {
        createEncryptedFileOk();

        final FileSystemOptions options = (FileSystemOptions) S3FileProvider.getDefaultFileSystemOptions().clone();

        S3FileSystemConfigBuilder.getInstance().setServerSideEncryption(options, true);

        FileObject dest = fsManager.resolveFile("s3://" + bucketName + "/test-place/output.txt", options);

        // Delete file if exists
        if (dest.exists()) {
            dest.delete();
        }

        // Copy data
        OutputStream os = dest.getContent().getOutputStream();
        try {
            os.write(BACKUP_ZIP.getBytes("US-ASCII"));
        } finally {
            os.close();
        }
        assertTrue(dest.exists() && dest.getType().equals(FileType.FILE));
        assertEquals(BACKUP_ZIP.length(), dest.getContent().getSize());
        assertEquals(AES_256_SERVER_SIDE_ENCRYPTION, ((S3FileObject)dest).getObjectMetadata().getSSEAlgorithm());

        BufferedReader reader = new BufferedReader(new InputStreamReader(dest.getContent().getInputStream(), "US-ASCII"));
        try {
            assertEquals(BACKUP_ZIP, reader.readLine());
        } finally {
            reader.close();
        }
        dest.delete();
    }

    @Test
    public void download() throws Exception
    {
        getSize();

        FileObject typica = fsManager.resolveFile("s3://" + bucketName + "/test-place/backup.zip");
        File localCache =  File.createTempFile("vfs.", ".s3-test");

        // Copy from S3 to localfs
        FileOutputStream out = new FileOutputStream(localCache);
        IOUtils.copy(typica.getContent().getInputStream(), out);

        // Test that file sizes equals
        assertEquals(localCache.length(), typica.getContent().getSize());

        assertTrue(localCache.delete());
    }

    @Test
    public void listChildren() throws FileSystemException
    {
        createDirOk();

        FileObject baseDir = fsManager.resolveFile(dir, "list-children-test");
        baseDir.createFolder();

        for (int i=0; i<5; i++) {
            FileObject tmpFile = fsManager.resolveFile(baseDir, i + ".tmp");
            tmpFile.createFile();
            tmpFile.exists();
        }

        FileObject[] children = baseDir.getChildren();
        assertEquals(5, children.length);
    }

    @Test
    public void listChildrenRoot() throws Exception
    {
        createDirOk();
        upload();
        uploadBigFile();
        createEncryptedFileOk();

        final String bucketUrl = "s3://" + bucketName + "/";

        assertHasChildren(fsManager.resolveFile(bucketUrl), "test-place", BIG_FILE);
        assertHasChildren(fsManager.resolveFile(bucketUrl + "test-place/"), "backup.zip", dirName, encryptedFileName, fileName);
        assertHasChildren(fsManager.resolveFile(bucketUrl + "test-place"), "backup.zip", dirName, encryptedFileName, fileName);

        final FileObject destFile = fsManager.resolveFile(bucketUrl + "test-place-2");

        destFile.copyFrom(fsManager.resolveFile(bucketUrl + "test-place"), SELECT_ALL);

        assertHasChildren(destFile, "backup.zip", dirName, encryptedFileName, fileName);
    }

    @Test
    public void findFiles() throws FileSystemException
    {
        createDirOk();

        FileObject baseDir = fsManager.resolveFile(dir, "find-tests");
        baseDir.createFolder();

        // Create files and dirs
        fsManager.resolveFile(baseDir, "child-file.tmp").createFile();
        fsManager.resolveFile(baseDir, "child-file2.tmp").createFile();
        fsManager.resolveFile(baseDir, "child-dir").createFolder();
        fsManager.resolveFile(baseDir, "child-dir/descendant.tmp").createFile();
        fsManager.resolveFile(baseDir, "child-dir/descendant2.tmp").createFile();
        fsManager.resolveFile(baseDir, "child-dir/descendant-dir").createFolder();

        FileObject[] files;
        files = baseDir.findFiles(Selectors.SELECT_CHILDREN);
        assertEquals(3, files.length);
        files = baseDir.findFiles(Selectors.SELECT_FOLDERS);
        assertEquals(3, files.length);
        files = baseDir.findFiles(Selectors.SELECT_FILES);
        assertEquals(4, files.length);
        files = baseDir.findFiles(Selectors.EXCLUDE_SELF);
        assertEquals(6, files.length);
    }

    @Test
    public void renameAndMove() throws Exception
    {
        upload();

        FileObject sourceFile = fsManager.resolveFile("s3://" + bucketName + "/test-place/" + fileName);
        FileObject targetFile = fsManager.resolveFile("s3://" + bucketName + "/test-place/rename-target");

        assertTrue(sourceFile.exists());

        if (targetFile.exists()) {
            targetFile.delete();
        }

        assertFalse(targetFile.exists());
        assertFalse(sourceFile.canRenameTo(targetFile));

        sourceFile.moveTo(targetFile);

        assertTrue(targetFile.exists());
        assertFalse(sourceFile.exists());

        targetFile.moveTo(sourceFile);

        assertTrue(sourceFile.exists());
        assertFalse(targetFile.exists());

        try {
            sourceFile.moveTo(sourceFile);

            fail(); // Should block copy into itself
        } catch (FileSystemException ignored) {
        }
    }

    @Test
    public void getType() throws FileSystemException
    {
        createDirOk();

        FileObject imagine = fsManager.resolveFile(dir, "imagine-there-is-no-countries");
        assertEquals(FileType.IMAGINARY, imagine.getType());
        assertEquals(FileType.FOLDER, dir.getType());
        assertEquals(FileType.FILE, file.getType());
    }

    @Test
    public void getTypeAfterCopyToSubFolder() throws FileSystemException
    {
        createDirOk();

        FileObject dest = fsManager.resolveFile(dir, "type-tests/sub1/sub2/backup.zip");

        // Copy data
        final File backupFile = new File(BACKUP_ZIP);

        assertTrue("Backup file should exists", backupFile.exists());

        FileObject src = fsManager.resolveFile(backupFile.getAbsolutePath());
        dest.copyFrom(src, Selectors.SELECT_SELF);

        assertTrue(dest.exists() && dest.getType().equals(FileType.FILE));

        FileObject sub1 = fsManager.resolveFile(dir, "type-tests/sub1");
        assertTrue(sub1.exists());
        assertTrue(sub1.getType().equals(FileType.FOLDER));

        FileObject sub2 = fsManager.resolveFile(dir, "type-tests/sub1/sub2");
        assertTrue(sub2.exists());
        assertTrue(sub2.getType().equals(FileType.FOLDER));
    }

    @Test
    public void getContentType() throws Exception
    {
        upload();

        FileObject backup = fsManager.resolveFile("s3://" + bucketName + "/test-place/backup.zip");
        assertEquals("application/zip", backup.getContent().getContentInfo().getContentType());
    }

    @Test
    public void getSize() throws Exception
    {
        upload();

        FileObject backup = fsManager.resolveFile("s3://" + bucketName + "/test-place/backup.zip");
        assertEquals(996166, backup.getContent().getSize());
    }

    @Test
    public void getUrls() throws Exception
    {
        upload();

        FileObject backup = fsManager.resolveFile("s3://" + bucketName + "/test-place/backup.zip");

        assertTrue(backup.getFileOperations().hasOperation(IPublicUrlsGetter.class));

        IPublicUrlsGetter urlsGetter = (IPublicUrlsGetter) backup.getFileOperations().getOperation(IPublicUrlsGetter.class);

        assertEquals("http://" + bucketName + ".s3.amazonaws.com/test-place/backup.zip", urlsGetter.getHttpUrl());
        assertTrue(urlsGetter.getPrivateUrl().endsWith("@" + bucketName + "/test-place/backup.zip"));

        final String signedUrl = urlsGetter.getSignedUrl(60);

        assertTrue(signedUrl.startsWith("https://" + bucketName + ".s3.amazonaws.com/test-place/backup.zip?"));
        assertTrue(signedUrl.contains("Signature="));
        assertTrue(signedUrl.contains("Expires="));
        assertTrue(signedUrl.contains("AWSAccessKeyId="));
    }

    @Test
    public void getMD5Hash() throws NoSuchAlgorithmException, IOException
    {
        upload();

        FileObject backup = fsManager.resolveFile("s3://" + bucketName + "/test-place/backup.zip");

        assertTrue(backup.getFileOperations().hasOperation(IMD5HashGetter.class));

        IMD5HashGetter md5Getter = (IMD5HashGetter) backup.getFileOperations().getOperation(IMD5HashGetter.class);

        String md5Remote = md5Getter.getMD5Hash();

        Assert.assertNotNull(md5Remote);

        final File backupFile = new File(BACKUP_ZIP);

        assertTrue("Backup file should exists", backupFile.exists());

        String md5Local = toHex(computeMD5Hash(new FileInputStream(backupFile)));

        assertEquals("Local and remote md5 should be equal", md5Remote, md5Local);
    }

    @Test
	public void copyInsideBucket() throws FileSystemException
    {
        findFiles();

        FileObject testsDir = fsManager.resolveFile(dir, "find-tests");
        FileObject testsDirCopy = testsDir.getParent().resolveFile("find-tests-copy");
        testsDirCopy.copyFrom(testsDir, Selectors.SELECT_SELF_AND_CHILDREN);

        // Should have same number of files
        FileObject[] files = testsDir.findFiles(Selectors.SELECT_SELF_AND_CHILDREN);
        FileObject[] filesCopy = testsDirCopy.findFiles(Selectors.SELECT_SELF_AND_CHILDREN);
        assertEquals(Arrays.deepToString(files) + " vs. " + Arrays.deepToString(filesCopy), files.length, filesCopy.length);
	}

    @Test
    public void copyAllToEncryptedInsideBucket() throws FileSystemException
    {
        findFiles();

        final FileSystemOptions options = (FileSystemOptions) S3FileProvider.getDefaultFileSystemOptions().clone();

        S3FileSystemConfigBuilder.getInstance().setServerSideEncryption(options, true);

        FileObject testsDir = fsManager.resolveFile(dir, "find-tests");
        FileObject testsDirCopy = fsManager.resolveFile("s3://" + bucketName + "/test-place/" + dirName, options).resolveFile("find-tests-encrypted-copy");

        testsDirCopy.copyFrom(testsDir, SELECT_ALL);

        // Should have same number of files
        FileObject[] files = testsDir.findFiles(SELECT_ALL);
        FileObject[] filesCopy = testsDirCopy.findFiles(SELECT_ALL);
        assertEquals(files.length, filesCopy.length);

        for (int i = 0; i < files.length; i++) {
            if (files[i].getType() == FileType.FILE) {
                assertEquals(null, ((S3FileObject)files[i]).getObjectMetadata().getSSEAlgorithm());
                assertEquals(AES_256_SERVER_SIDE_ENCRYPTION, ((S3FileObject)filesCopy[i]).getObjectMetadata().getSSEAlgorithm());
            }
        }
    }

    @Test
    public void delete() throws Exception
    {
        findFiles();
        download();

        FileObject testsDir = fsManager.resolveFile(dir, "find-tests");
        testsDir.delete(Selectors.EXCLUDE_SELF);

        // Only tests dir must remains
        FileObject[] files = testsDir.findFiles(SELECT_ALL);
        assertEquals(1, files.length);
    }

    @After
    public void tearDown() throws FileSystemException
    {
        try {
            fsManager.resolveFile("s3://" + bucketName + "/" + BIG_FILE).delete();
            fsManager.resolveFile("s3://" + bucketName + "/test-place").delete(SELECT_ALL);
            fsManager.resolveFile("s3://" + bucketName + "/test-place-2").delete(SELECT_ALL);

            ((AbstractFileSystem) fsManager.resolveFile("s3://" + bucketName + "/").getFileSystem()).close();
        } catch (Exception ignored) {
        }
    }


    /**
     * Converts byte data to a Hex-encoded string.
     *
     * @param data data to hex encode.
     * @return hex-encoded string.
     */
    private String toHex(byte[] data)
    {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte aData : data) {
            String hex = Integer.toHexString(aData);
            if (hex.length() == 1) {
                // Append leading zero.
                sb.append("0");
            } else if (hex.length() == 8) {
                // Remove ff prefix from negative numbers.
                hex = hex.substring(6);
            }
            sb.append(hex);
        }
        return sb.toString().toLowerCase(Locale.getDefault());
    }


    private byte[] computeMD5Hash(InputStream is) throws NoSuchAlgorithmException, IOException
    {
        BufferedInputStream bis = new BufferedInputStream(is);
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            byte[] buffer = new byte[16384];
            int bytesRead;
            while ((bytesRead = bis.read(buffer, 0, buffer.length)) != -1) {
                messageDigest.update(buffer, 0, bytesRead);
            }
            return messageDigest.digest();
        } finally {
            try {
                bis.close();
            } catch (Exception e) {
                System.err.println("Unable to close input stream of hash candidate: " + e);
            }
        }
    }
}
