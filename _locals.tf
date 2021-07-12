locals {
  env       = "home"
  envs      = ["dev", "stag", "prod"]
  one_hour  = 3600
  one_day   = local.one_hour * 24
  one_month = local.one_day * 30
  one_year  = local.one_day * 365
  ten_years = local.one_year * 10
}