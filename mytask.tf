provider "aws" {
     region = "ap-south-1"
     profile = "hardikagarwal"
}

resource "aws_security_group" "sg1" {
  name        = "sg1"
  description = "Allows port 80 and 22"
  

  ingress {
    description = "port 80 for http protocol"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "port 20 for ssh protocol"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "sg1"
  }
}

resource "tls_private_key" "keypair1" {
  algorithm   = "RSA"
  
}

resource "local_file" "key_local" {
     content  = tls_private_key.keypair1.private_key_pem
     filename = "keypair1.pem"
}

resource "aws_key_pair" "keypair1"{
      key_name = "keypair1"
      public_key = tls_private_key.keypair1.public_key_openssh
}

resource "aws_instance" "os1" {
     ami = "ami-0447a12f28fddb066"
     instance_type = "t2.micro"
     availability_zone = "ap-south-1a"
     key_name = aws_key_pair.keypair1.key_name
     security_groups = ["${aws_security_group.sg1.tags.Name}"]

 connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.keypair1.private_key_pem
    host     = aws_instance.os1.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo yum install httpd git -y",
      "sudo systemctl restart httpd",
      "sudo systemctl enable httpd",
    ]
  }
     
 
     tags = {
              Name= "os1" 
            }
}

resource "aws_ebs_volume" "volume1" {
  availability_zone = "ap-south-1a"
  size              = 10

  tags = {
    Name = "volume1"
  }
}

resource "aws_volume_attachment" "volume_attach" {
  device_name = "/dev/sdh"
  volume_id   = aws_ebs_volume.volume1.id
  instance_id = aws_instance.os1.id
  force_detach = true
}

resource "null_resource" "partition"  {

depends_on = [
    aws_volume_attachment.volume_attach
  ]


  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.keypair1.private_key_pem
    host     = aws_instance.os1.public_ip
  }

   provisioner "remote-exec" {
    inline = [
      "sudo mkfs.ext4  /dev/xvdh",
      "sudo mount  /dev/xvdh  /var/www/html",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/agarwalhardik/cloud.git /var/www/html"
    ]
  }
}
resource "aws_s3_bucket" "hardiktaskbucket" {
  bucket = "hardiktaskbucket"
  acl    = "public-read"

  tags = {
    Name        = "hardiktaskbucket"
    Environment = "dev"
  }
}

locals {
  s3_origin_id = "hardik_s3_origin"
}

data "aws_iam_policy_document" "s3_bucket_policy" {
      statement {
          actions   = ["s3:GetObject"]
          resources = ["${aws_s3_bucket.hardiktaskbucket.arn}/*"]

          principals {
              type        = "AWS"
              identifiers = ["${aws_cloudfront_origin_access_identity.OAI.iam_arn}"]
          }
      }

      statement {
          actions   = ["s3:ListBucket"]
          resources = ["${aws_s3_bucket.hardiktaskbucket.arn}"]

          principals {
              type        = "AWS"
              identifiers = ["${aws_cloudfront_origin_access_identity.OAI.iam_arn}"]
          }
      }
}


resource "aws_s3_bucket_policy" "bucket_policy" {
  depends_on = [
        aws_s3_bucket.hardiktaskbucket
  ]
  bucket = "${aws_s3_bucket.hardiktaskbucket.id}"
  policy = data.aws_iam_policy_document.s3_bucket_policy.json
}


resource "aws_s3_bucket_object" "object" {
  depends_on = [
          aws_s3_bucket.hardiktaskbucket
  ]
  bucket = "hardiktaskbucket"
  key    = "john.jpg"
  source = "C:/Users/dell/Downloads/john.jpg"
  acl    = "public-read"
}

resource "aws_cloudfront_origin_access_identity" "OAI" {
      comment = "access-identity-hb"
}


resource "aws_cloudfront_distribution" "s3_distribution" {
   depends_on = [
          aws_s3_bucket.hardiktaskbucket,
          aws_cloudfront_origin_access_identity.OAI
   ]
      
   origin {
    domain_name = "${aws_s3_bucket.hardiktaskbucket.bucket_regional_domain_name}"
    origin_id   = "${local.s3_origin_id}"
    
    s3_origin_config {
              origin_access_identity = "origin-access-identity/cloudfront/${aws_cloudfront_origin_access_identity.OAI.id}"
          }
   }

     enabled = true
     is_ipv6_enabled = true

   restrictions {
    geo_restriction {
      restriction_type = "none"
    }
   }
  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${aws_s3_bucket.hardiktaskbucket.id}"
   
    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

 viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }


viewer_certificate {
    cloudfront_default_certificate = true
  }
}

resource "null_resource" "update_URL" {
      depends_on = [
          aws_cloudfront_distribution.s3_distribution
      ]

      connection {
          type     = "ssh"
          user     = "ec2-user"
          private_key = tls_private_key.keypair1.private_key_pem
          host     = aws_instance.os1.public_ip
      }

      provisioner "remote-exec" {
          inline = [
              "sudo sed 's/john.jpg/${aws_cloudfront_distribution.s3_distribution.domain_name}|g' /var/www/html/task1.html"
          ]
      }
}

resource "null_resource" "open_webpage" {
      depends_on = [
          aws_cloudfront_distribution.s3_distribution,
          null_resource.update_URL
      ]

      provisioner "local-exec" {
          command = "chrome http://${aws_instance.os1.public_ip}/task1.html &"
      }

}