resource "aws_s3_bucket" "example" {
  bucket = "vulntracker-devsecops-demo"
}

resource "aws_security_group" "example" {
  name = "vulntracker-demo"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}