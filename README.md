# Demo App "Pet Clinic" backed by HashiCorp Vault with HA
## Getting Started
This repo contains a demo app ["Pet Clinic"](https://github.com/spring-projects/spring-petclinic), backed by a HashiCorp Vault cluster with HA and AWS DynamoDB.

## Prerequesites
* Terraform > 0.13. If you are using an older version of Terraform then you WILL receive an error. Download the [latest terraform here](https://releases.hashicorp.com/terraform/) and unzip it to your `$PATH`.
* A valid AWS account. Ensure that you have configure your account's access keys via `aws configure`, with `default` profile set up
* A valid Datadog account. Ensure that you have signed up for a [Datadog account](https://app.datadoghq.com/signup). You will need an API key created from your Datadog account to install the agent on the end nodes.

## Deployment
Steps:
- `terraform init`
- `terraform plan`
- `terraform apply`
