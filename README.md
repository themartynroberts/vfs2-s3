Amazon S3 driver for VFS (Apache Commons Virtual File System)
=============================================================


Sample Java Code
----------------

	// Create bucket
	FileSystemManager fsManager = VFS.getManager();
	FileObject dir = fsManager.resolveFile("s3://simple-bucket/test-folder/");
	dir.createFolder();

	// Upload file to S3
	FileObject dest = fsManager.resolveFile("s3://test-bucket/backup.zip");
	FileObject src = fsManager.resolveFile(new File("/path/to/local/file.zip").getAbsolutePath());
	dest.copyFrom(src, Selectors.SELECT_SELF);


Running the tests
-----------------
For running tests you need active credentials for AWS. You can specify them as VM parameters e.g.
-Daws.accessKey=ABCD
-Daws.secretKey=ABCD
-Ds3.testBucket=abcd-tests

**Make sure that you never commit your credentials!**

This code is based on <https://github.com/abashev/vfs-s3>
