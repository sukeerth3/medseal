# MedSeal Infrastructure

## Remote State

Terraform currently keeps local state. To move to remote state later:

1. Create a private S3 bucket for Terraform state with versioning and default encryption enabled.
2. Create a DynamoDB table for state locking with a string hash key named `LockID`.
3. Update the example bucket, lock table, region, and state key in `backend.tf`.
4. Run `terraform init -migrate-state` from `infrastructure/`.

Do not run migration until the bucket and lock table are ready and the current local state has been backed up.

## PCR Inputs

Build the EIF on a Nitro-capable host and write PCR values into Terraform variables:

```bash
./scripts/extract-pcrs.sh build/medseal.eif > infrastructure/pcrs.auto.tfvars
```

The root module requires `allowed_pcr0`, `allowed_pcr1`, and `allowed_pcr2`. The KMS key resource refuses empty or placeholder values.

## Dev Teardown

Dev/demo stacks default `s3_force_destroy = true` so `terraform destroy`
can delete the versioned results bucket without a manual S3 version cleanup.
The S3 module refuses that setting outside `environment = "dev"`; set
`s3_force_destroy = false` before using staging or production retention
workflows.
