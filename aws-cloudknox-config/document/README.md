# CloudKnox - Right Size Automation Document

### Steps to follow

1. Init your env with AWS credentials
1. Create (or use an existing) bucket to push the python code
1. Deploy the ck_right_size_iam_cfn.yaml cloudformation role
1. Replace the place holder REPLACE_WITH_ROLE_ARN with the role arn in ck_right_size_runbook.yaml
1. Deploy the automation document using the CLI
  ```bash
    # Sample
    S3_BUCKET_PATH=<add s3 bucket path excluding the file name>
    aws ssm create-document \
      --name ck-right-size-ssm-doc-remote-us-west-2 \
      --content file://ck_right_size_runbook.yaml \
      --document-format YAML \
      --attachments Key=SourceUrl,Values="${S3_BUCKET_PATH}" \
      --document-type Automation
  ```
