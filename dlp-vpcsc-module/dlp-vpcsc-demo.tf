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





# Create the DLP Project
resource "google_project" "dlp_project" {
  project_id      = "${var.demo_project_id}${var.dlptag}${var.vpcsctag}${var.random_string}"
  name            = "SF Solution - Data Analytics"
  billing_account = var.billing_account
  folder_id = var.folder_id
  }



# Enable the necessary API services
resource "google_project_service" "dlp_api_service" {
  for_each = toset([
    "cloudbuild.googleapis.com",
    "dlp.googleapis.com",
    "cloudfunctions.googleapis.com",
    "logging.googleapis.com",
    "pubsub.googleapis.com",
    "accesscontextmanager.googleapis.com",
    "compute.googleapis.com",
    "bigquery.googleapis.com",
  ])

  service = each.key

  project            = google_project.dlp_project.project_id
  disable_on_destroy = true
  disable_dependent_services = true
}


# Wait delay after enabling APIs
resource "time_sleep" "wait_120_seconds_enable_service_api_dlp" {
  depends_on = [google_project_service.dlp_api_service]
  create_duration = "120s"
  destroy_duration = "5m"
}

#Creating Staging/QA storage bucket
resource "google_storage_bucket" "cloud_qa_storage_bucket_name" {
  name          = "${var.qa_storage_bucket_name}${var.random_string}"
  location      = var.network_region
  force_destroy = true
  project       = google_project.dlp_project.project_id
  uniform_bucket_level_access = true
}

#Creating storage bucket for sensitive data
resource "google_storage_bucket" "cloud_sens_storage_bucket_name" {
  name          = "${var.sens_storage_bucket_name}${var.random_string}"
  location      = var.network_region
  force_destroy = true
  project       = google_project.dlp_project.project_id
  uniform_bucket_level_access = true
}

#Creating storage bucket for non-sensitive data
resource "google_storage_bucket" "cloud_nonsens_storage_bucket_name" {
  name          = "${var.nonsens_storage_bucket_name}${var.random_string}"
  location      = var.network_region
  force_destroy = true
  project       = google_project.dlp_project.project_id
  uniform_bucket_level_access = true
}

#Create the service Account for DLP function
resource "google_service_account" "def_ser_acc" {
   project = google_project.dlp_project.project_id
   account_id   = "appengine-service-account"
   display_name = "AppEngine Service Account"
   depends_on = [google_project_service.dlp_api_service]
 }


# Add required roles to the service accounts
  resource "google_project_iam_member" "service_dlp_admin" {
   project = google_project.dlp_project.project_id
   role    = "roles/dlp.admin"
   member  = "serviceAccount:${google_service_account.def_ser_acc.email}"
   depends_on = [google_service_account.def_ser_acc]
  }

# Add required roles to the service accounts
  resource "google_project_iam_member" "ser_agent" {
    project = google_project.dlp_project.project_id
    role    = "roles/dlp.serviceAgent"
    member  = "serviceAccount:${google_service_account.def_ser_acc.email}"
    depends_on = [google_service_account.def_ser_acc]
  }

  # Add required roles to the service accounts
  resource "google_project_iam_member" "proj_editor" {
   project = google_project.dlp_project.project_id
   role    = "roles/owner"
   member  = "serviceAccount:${google_service_account.def_ser_acc.email}"
   depends_on = [google_service_account.def_ser_acc]
  }


# Creates zip file of function code & requirments.txt
data "archive_file" "source" {
    type        = "zip"
    source_dir  = "${path.module}/application"
    output_path = "${path.module}/dlpfunction.zip"
    depends_on = [google_project_service.dlp_api_service]
}

#Creating the bucket for python source code
resource "google_storage_bucket" "application" {
  name     = "application-${var.demo_project_id}${var.dlptag}${var.random_string}"
  location      = var.network_region
  force_destroy = true
  project       = google_project.dlp_project.project_id
  uniform_bucket_level_access = true
}

# Add zip file to the Cloud Function's source code bucket
resource "google_storage_bucket_object" "python_code" {
  name   = "dlpfunction.zip"
  bucket = google_storage_bucket.application.name
  source = "${path.module}/dlpfunction.zip"
}

#Creating the pubsub topic
resource "google_pubsub_topic" "pubsub_topic" {
  name = var.pubsub_topic_name
  project = google_project.dlp_project.project_id
  }

#Creating the pubsub subscription
resource "google_pubsub_subscription" "pubsub_subscription" {
  name  = var.pubsub_subscription_name
  project = google_project.dlp_project.project_id
  topic = google_pubsub_topic.pubsub_topic.name
  
}

# Create the DLP Functions
resource "google_cloudfunctions_function" "create_DLP_job" {
  name        = "create_DLP_job"
  description = "Create DLP Job"
  runtime     = "python37"
  project     = google_project.dlp_project.project_id
  region      = var.network_region
  ingress_settings = "ALLOW_INTERNAL_AND_GCLB"
  
  available_memory_mb   = 512
  source_archive_bucket = google_storage_bucket.application.name
  source_archive_object = google_storage_bucket_object.python_code.name
   entry_point           = "create_DLP_job"
  service_account_email = "${google_service_account.def_ser_acc.email}"
  
  event_trigger {
        event_type = "google.storage.object.finalize"
        resource   = "${var.qa_storage_bucket_name}${var.random_string}"  # quarantine bucket where files are uploaded for processing
    }

  depends_on = [time_sleep.wait_120_seconds_enable_service_api_dlp]

  environment_variables = {
    PROJ_ID      = google_project.dlp_project.project_id
    QA_BUCKET    = google_storage_bucket.cloud_qa_storage_bucket_name.name
    SENS_BUCKET  = google_storage_bucket.cloud_sens_storage_bucket_name.name
    NONS_BUCKET  = google_storage_bucket.cloud_nonsens_storage_bucket_name.name
    PB_SB_TOP    = var.pubsub_topic_name
  }
}

resource "google_cloudfunctions_function" "resolve_DLP" {
  name        = "resolve_DLP"
  description = "Resolve DLP"
  runtime     = "python37"
  project     = google_project.dlp_project.project_id
  region      = var.network_region
  ingress_settings = "ALLOW_INTERNAL_AND_GCLB"
  
  available_memory_mb   = 512
  source_archive_bucket = google_storage_bucket.application.name
  source_archive_object = google_storage_bucket_object.python_code.name
  entry_point           = "resolve_DLP"
  service_account_email = "${google_service_account.def_ser_acc.email}"
  
    event_trigger {
        event_type = "google.pubsub.topic.publish"
        resource   = "projects/${var.demo_project_id}${var.dlptag}${var.vpcsctag}${var.random_string}/topics/${var.pubsub_topic_name}"   
    }
  
  depends_on = [time_sleep.wait_120_seconds_enable_service_api_dlp]

  environment_variables = {
   PROJ_ID      = google_project.dlp_project.project_id
    QA_BUCKET    = google_storage_bucket.cloud_qa_storage_bucket_name.name
    SENS_BUCKET  = google_storage_bucket.cloud_sens_storage_bucket_name.name
    NONS_BUCKET  = google_storage_bucket.cloud_nonsens_storage_bucket_name.name
    PB_SB_TOP    = var.pubsub_topic_name
     }
}



## VPC SC PoC Code

#Creating  storage bucket
resource "google_storage_bucket" "vpc_sc_storage_bucket_name" {
  name          = "${var.vpcsctag}${var.random_string}"
  location      = var.network_region
  force_destroy = true
  project       = google_project.dlp_project.project_id
  uniform_bucket_level_access = true
  depends_on              = [time_sleep.wait_120_seconds_enable_service_api_dlp]
}

# Add a sample file to the storage bucket
resource "google_storage_bucket_object" "shop_data_file" {
  name   = "shop-data"
  bucket = google_storage_bucket.vpc_sc_storage_bucket_name.name
  source = "${path.module}/sample_data/shop_data.csv"
  depends_on              = [google_storage_bucket.vpc_sc_storage_bucket_name]
}


# Create dataset in bigquery
resource "google_bigquery_dataset" "shop_dataset" {
  dataset_id = "shop_dataset"
  location   = var.network_region
  project       = google_project.dlp_project.project_id
  depends_on              = [time_sleep.wait_120_seconds_enable_service_api_dlp]

}

# Create table in bigquery
resource "google_bigquery_table" "shop_table" {
  dataset_id          = google_bigquery_dataset.shop_dataset.dataset_id
  project             = google_project.dlp_project.project_id
  table_id            = "shop_data"
  description         = "This table contain sales data of Shop"
  deletion_protection = false
  depends_on              = [google_bigquery_dataset.shop_dataset]
}

# Import data in table 
resource "google_bigquery_job" "import_job" {
    project             = google_project.dlp_project.project_id
  job_id   = "job_import_${var.random_string}"
  location = var.network_region

  labels = {
    "my_job" = "load"
  }

  load {
    source_uris = [
      "gs://${google_storage_bucket.vpc_sc_storage_bucket_name.name}/${google_storage_bucket_object.shop_data_file.name}",
    ]

    destination_table {
      project_id = google_bigquery_table.shop_table.project
      dataset_id = google_bigquery_table.shop_table.dataset_id
      table_id   = google_bigquery_table.shop_table.table_id
    }
    skip_leading_rows = 0
    autodetect        = true

  }
  depends_on              = [google_bigquery_table.shop_table]
  
}

# Assign privileges to terraform Service Account
resource "google_service_account" "terraform_service_account" {
  project = google_project.dlp_project.project_id
  account_id   = "terraform-service-account"
  display_name = "Terraform Service Account"
  depends_on = [google_project_service.dlp_api_service]
}

resource "google_organization_iam_member" "service_usage_admin" {
  org_id  = var.organization_id
  role    = "roles/serviceusage.serviceUsageAdmin"
  member  = var.proxy_access_identities
depends_on = [google_project_service.dlp_api_service]

}

resource "google_organization_iam_member" "access_context_manager_admin" {
  org_id  = var.organization_id
  role    = "roles/accesscontextmanager.policyAdmin"
  member  = var.proxy_access_identities
depends_on = [google_project_service.dlp_api_service]

}

resource "google_organization_iam_member" "organization_viewer" {
  org_id  = var.organization_id
  role    = "roles/resourcemanager.organizationViewer"
  member  = var.proxy_access_identities
depends_on = [google_project_service.dlp_api_service]

}

resource "google_organization_iam_member" "organization_role_viewer" {
  org_id  = var.organization_id
  role    = "roles/iam.organizationRoleViewer"
  member  = var.proxy_access_identities
depends_on = [google_project_service.dlp_api_service]

}



resource "google_access_context_manager_access_policy" "default" {
  count = var.create_default_access_policy ? 1 : 0
  provider = google.service
  parent = "organizations/${var.organization_id}"
  title  = "Default Org Access Policy"
  depends_on              = [
      google_storage_bucket_object.shop_data_file,
      google_bigquery_job.import_job,
      ]
  
}

resource "google_access_context_manager_access_policy" "vpc_sc_demo_policy" {
  provider = google.service
  parent = "organizations/${var.organization_id}"
  title  = "VPC SC demo policy"
  scopes = ["projects/${google_project.dlp_project.number}"]
  depends_on = [
      google_access_context_manager_access_policy.default,
      time_sleep.wait_120_seconds_enable_service_api_dlp,
      ]
}

resource "google_access_context_manager_service_perimeter" "service-perimeter" {
  provider = google.service
  parent = "accessPolicies/${google_access_context_manager_access_policy.vpc_sc_demo_policy.name}"
  name   = "accessPolicies/${google_access_context_manager_access_policy.vpc_sc_demo_policy.name}/servicePerimeters/restrict_service_api"
  title  = "restrict_service_api"
#   use_explicit_dry_run_spec = true
#   spec {
#     restricted_services = [
#    "storage.googleapis.com",
#       ]
#     resources = ["projects/${google_project.xyz.number}"]
#     vpc_accessible_services {
#         enable_restriction = false        
#     }
#     ingress_policies {
#         ingress_from {
#             identities = ["user:${var.user_id}", "serviceAccount:${google_service_account.abcd.email}"]
#             sources {
#                 resource = "projects/${google_project.abcd.number}"
#             }
#         }
#         ingress_to { 
#             resources = [ "projects/${google_project.xyz.number}" ]
#             operations {
#                 service_name = "*"
#             } 
#         }
#     }
#   }
  status {
    restricted_services = [
    #    "bigquery.googleapis.com",
        "compute.googleapis.com",
        ]
    resources = ["projects/${google_project.dlp_project.number}"]
    vpc_accessible_services {
        enable_restriction = false        
    }
    ingress_policies {
      
    }
  }
  depends_on              = [google_access_context_manager_access_policy.vpc_sc_demo_policy]
}


