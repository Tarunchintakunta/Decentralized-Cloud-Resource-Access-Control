# terraform/aws/main.tf
provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_role" "lambda_role" {
  name = "frost_lambda_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "frost_lambda_policy"
  role = aws_iam_role.lambda_role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*",
      "Effect": "Allow"
    },
    {
      "Action": [
        "iam:GetRole",
        "iam:GetPolicy",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:ListAttachedRolePolicies"
      ],
      "Resource": "*",
      "Effect": "Allow"
    }
  ]
}
EOF
}

resource "aws_lambda_function" "frost_access_handler" {
  filename      = "lambda_function.zip"
  function_name = "frost_access_handler"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "nodejs16.x"
  timeout       = 30

  environment {
    variables = {
      CONTRACT_ADDRESS = "0x0000000000000000000000000000000000000000" # To be updated after deployment
      PROVIDER_URL     = "https://mainnet.infura.io/v3/YOUR_INFURA_KEY" # Replace with your Ethereum node URL
    }
  }
}

resource "aws_api_gateway_rest_api" "frost_api" {
  name        = "FROST-AccessControl-API"
  description = "API Gateway for FROST threshold access control"
}

resource "aws_api_gateway_resource" "access" {
  rest_api_id = aws_api_gateway_rest_api.frost_api.id
  parent_id   = aws_api_gateway_rest_api.frost_api.root_resource_id
  path_part   = "access"
}

resource "aws_api_gateway_method" "access_post" {
  rest_api_id   = aws_api_gateway_rest_api.frost_api.id
  resource_id   = aws_api_gateway_resource.access.id
  http_method   = "POST"
  authorization_type = "NONE"
}

resource "aws_api_gateway_integration" "lambda_integration" {
  rest_api_id = aws_api_gateway_rest_api.frost_api.id
  resource_id = aws_api_gateway_resource.access.id
  http_method = aws_api_gateway_method.access_post.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.frost_access_handler.invoke_arn
}

resource "aws_api_gateway_deployment" "frost_deployment" {
  depends_on = [
    aws_api_gateway_integration.lambda_integration
  ]

  rest_api_id = aws_api_gateway_rest_api.frost_api.id
  stage_name  = "prod"
}

output "api_gateway_url" {
  value = "${aws_api_gateway_deployment.frost_deployment.invoke_url}/access"
}