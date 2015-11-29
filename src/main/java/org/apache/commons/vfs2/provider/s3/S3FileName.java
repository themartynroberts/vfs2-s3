/*
 * Copyright 2007 Matthias L. Jugel.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.commons.vfs2.provider.s3;

import org.apache.commons.vfs2.FileName;
import org.apache.commons.vfs2.FileType;
import org.apache.commons.vfs2.provider.AbstractFileName;

public class S3FileName extends AbstractFileName
{
    private final String bucketName;

    public String getBucketName()
    {
        return bucketName;
    }

    public S3FileName(final String scheme, final String bucketName, final String path, final FileType type)
    {
        super(scheme, path, type);
        this.bucketName = bucketName;
    }

    @Override
    public FileName createName(final String absPath, final FileType type)
    {
        return new S3FileName(getScheme(), bucketName, absPath, type);
    }

    @Override
    protected void appendRootUri(final StringBuilder buffer, final boolean addPassword)
    {
        buffer.append(getScheme()).append("://").append(bucketName);
    }
}
