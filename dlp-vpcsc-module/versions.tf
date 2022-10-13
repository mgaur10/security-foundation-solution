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

terraform {
  required_version = ">= 1.1.0"
  required_providers {
    google = {
      source  = "registry.terraform.io/hashicorp/google"
      
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 4.32.0" # tftest
    }
  }
}

provider "google" {
    alias = "service"
user_project_override = true
billing_project = google_project.dlp_project.project_id
}

