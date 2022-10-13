/**
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


## NOTE: This provides PoC demo environment for various use cases ##
##  This is not built for production workload ##


variable organization_id {
}

variable billing_account {    
}

variable folder_name {
}


variable demo_project_id {
}


variable vpc_network_name {
}


 variable network_zone{
 }


  variable network_region {
 }

variable "cloud_sql_proxy_version" {
  description = "Which version to use of the Cloud SQL proxy."
  type        = string
  default     = "v1.31.1"
}



variable "proxy_access_identities" {
  description = "Identity who require access to the SQL proxy, and database.  Every identity should be prefixed with the type, for example user:, serviceAccount: and/or group:"
  type        = string
 # default     = "user:abc@xyz.com"
}




variable keyring_name {
}

variable crypto_key_name {
}

 variable "labels" {
  description = "Labels, provided as a map"
  type        = map(string)
}


variable "deployment_name" {
  type        = string
  description = "The name of this particular deployment, will get added as a prefix to most resources."
  default     = "three-tier-app"
}


variable "app-labels" {
  type        = map(string)
  description = "A map of labels to apply to contained resources."
  default     = { "three-tier-app" = true }
}

variable "memorystore" {
  type        = bool
  description = "If true, Online Boutique's in-cluster Redis cache will be replaced with a Google Cloud Memorystore Redis cache"
  default = false
}
