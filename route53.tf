resource "aws_route53_record" "www" {
  zone_id = var.r53_zone_id
  name    = var.r53_record_name
  type    = "A"

  alias {
    name                   = aws_lb.api.dns_name
    zone_id                = aws_lb.api.zone_id
    evaluate_target_health = true
  }
}