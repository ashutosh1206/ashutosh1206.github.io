---
title: "Backing up a large Postgres DB to S3"
date: 2024-12-28
author: Ashutosh Ahelleya
---

I recently backed up a large PostgreSQL database, spanning a few dozen terabytes, from AWS RDS to an AWS S3 bucket in a resource-constrained environment. The process wasn't as straightforward as I imagined it would be, so I decided to share everything I learned.

Let's say we have limited storage on the machine where we want to back up the database -- meaning the size of the backup exceeds the total storage capacity of the machine. Additionally, our priority is the speed at which this backup is taken rather than the cost of storing it in S3. Let's explore how we can perform a backup under these constraints. If you don't have the same constraints, you may want to tweak a few parameters which we'll discuss after the tl;dr section.

This blog post specifically covers the scenario where there's no other option but to back up a large PostgreSQL DB to S3. If the large database is going to be restored elsewhere immediately after, it is more efficient to restore it on the fly without using S3, as detailed [here](https://www.linkedin.com/pulse/how-speed-up-pgdump-when-dumping-large-postgres-nikolay-samokhvalov/).

## Why not just take a snapshot on RDS?

There are a few reasons why RDS snapshots may not be suitable:

- **Reduce allocated storage**: AWS does not allow reducing allocated storage on an RDS instance as easily at it allows increasing it. Until very recently (December 2024), `pg_dump`/`pg_restore` was the only viable way to reduce allocated storage ([stackoverflow](https://stackoverflow.com/a/36747127)). However, since then AWS has introduced green/blue deployments ([source](https://aws.amazon.com/blogs/database/shrink-storage-volumes-for-your-rds-databases-and-optimize-your-infrastructure-costs/)) which supported storage shrinking ([announcement](https://aws.amazon.com/about-aws/whats-new/2024/11/amazon-rds-blue-green-deployments-storage-volume-shrink/))
- **Migrating the database**: When moving a database off RDS to another cloud provider or to a self-hosted environment, snapshots do not provide the flexibility for such migrations.

Additionally, even if snapshots are exported to S3, AWS doesn't provide a way to restore snapshot data from S3:

![S3-snapshot-warning](/rds-snapshot-warning.png)
*Image Source*: <https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ExportSnapshot.html>

## tl;dr just give me the commands

```bash
# Set multipart chunksize to 1GB
aws configure set default.s3.multipart_chunksize 1GB

# Dump database without compression (for speed)
# Split the backup into files of size 1TB
# Upload each file with prefix `dump_split` to S3
pg_dump -h <rds-hostname> -U <rds-username> -d <database-name> -F c -Z0 | split -b 1000000000000 - dump_split --filter 'aws s3 cp - "s3://<bucket-name>/<path-to-file>/$FILE" --checksum-algorithm CRC'

# Don't forget to unset the multipart chunksize value after the backup, if needed :)
```

If rising storage costs from the backup are a concern, lifecycle rules on the S3 bucket can be configured to move files to the Glacier storage class after a certain period, significantly reducing costs compared to the standard class (see [here](https://aws.amazon.com/s3/pricing/)).

Now that we have all the commands we need to take a backup, let's analyze the rationale behind the approach:

- **Direct Streaming to S3**: Given the storage constraints, we opted to stream the backup directly to an S3 bucket. While this approach is reliable, it introduced a trade-off, as S3 upload speed became the bottleneck due to the blocking nature of shell pipes. This is an acceptable compromise under the given constraints.
- **Disabling Compression**: The compression level is set to 0 (`-Z0`) to maximize backup speed, as enabling compression significantly slows down the `pg_dump` process. If storage cost optimization is a higher priority than backup speed, consider removing the `-Z0` flag or setting it to an appropriate compression level.
- **Avoiding the directory format with pg_dump**: We use the custom output format with `pg_dump` instead of the directory format, even though the latter allows parallelization of `pg_dump` jobs, because the directory format isn't suitable for S3 uploads.

## Why split the backup into files of size 1 TB?

There is a **maximum limit on the size of an object** that can be uploaded to AWS S3 via multipart upload -- **5 TiB** (see [here](https://docs.aws.amazon.com/AmazonS3/latest/userguide/qfacts.html)). To upload an object more than 5 TiB, it must be split into smaller blobs, with each part uploaded to S3. This limitation is why we used `split -b 1000000000000 - dump_split` in our command.

![pg_limits](/s3-limits.png)
*Image source*: <https://docs.aws.amazon.com/AmazonS3/latest/userguide/qfacts.html>

## Why set the multipart chunk-size for S3?

The maximum number of parts per object in a multipart upload is 10,000. Additionally, if the number of chunks to upload an object is more than 10,000, we won't know until the last part of the object is uploaded that the upload failed due to this reason, which can be frustrating and time-consuming.

To counter this, we preemptively configure the size of each chunk that's uploaded via multipart upload, using the `multipart_chunksize` setting. Several factors determine the optimal chunk size for faster uploads, including CPU, latency, and network capacity. For the purpose of this blog post, we arbitrarily select 1 GB as the chunk size. For objects around 1 TB in size, the number of chunks would be approximately 1,000, well below the maximum number of allowed parts.
