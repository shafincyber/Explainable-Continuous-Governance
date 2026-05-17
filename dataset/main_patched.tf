provider "aws" { region = "eu-central-1" }
resource "aws_s3_bucket" "ai_training_data" {
  bucket = "shafin-ai-training-data-eu"
}

resource "aws_iam_policy" "permissive_policy" {
  name        = "allow-all"
  policy      = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action    = "s3:ListBucket",
        Effect    = "Allow",
        Resource  = aws_s3_bucket.ai_training_data.arn,
      },
      {
        Action    = "s3:GetObject",
        Effect    = "Allow",
        Resource  = "${aws_s3_bucket.ai_training_data.arn}/*",
      },
    ]
  })
}