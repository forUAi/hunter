provider "aws" {}
resource "aws_s3_bucket" "reports" {
  bucket = "fixture-reports"
}
