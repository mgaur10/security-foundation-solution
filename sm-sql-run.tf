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





#Create the service Account
resource "google_service_account" "def_ser_acc" {
   project = google_project.demo_project.project_id
   account_id   = "sa-service-account"
   display_name = "CLoud SQL Service Account"
 }


data "google_project" "project" {
  project_id = google_project.demo_project.project_id
}

locals {
  sabuild   = "${data.google_project.project.number}@cloudbuild.gserviceaccount.com"
  api_image = "gcr.io/sic-container-repo/todo-api"
  fe_image  = "gcr.io/sic-container-repo/todo-fe"
}


# Create a service account for Cloud Run
resource "google_service_account" "runsa" {
  project      = google_project.demo_project.project_id
  account_id   = "${var.deployment_name}-run-sa"
  display_name = "Service Account for Cloud Run"
}

# Create the secret manager accessor role for service account
resource "google_project_iam_member" "allrun" {
  project    = data.google_project.project.number
  role       = "roles/secretmanager.secretAccessor"
  member     = "serviceAccount:${google_service_account.runsa.email}"
  depends_on = [time_sleep.wait_120_seconds_enable_service_api]
}


# Create the VPC connector for Cloud Run access to VPC network
resource "google_vpc_access_connector" "main" {
  provider       = google-beta
  project        = google_project.demo_project.project_id
  name           = "${var.deployment_name}-vpc-cx"
  ip_cidr_range  = "10.8.0.0/28"
  network        = google_compute_network.host_network.self_link
  region         = var.network_region
  max_throughput = 300
  depends_on     = [time_sleep.wait_120_seconds_enable_service_api]
}

# Create a random id for the DB instance to avoid collision
resource "random_id" "id" {
  byte_length = 2
}

#  Database Instance
resource "google_sql_database_instance" "main" {
  name             = "${var.deployment_name}-db-${random_id.id.hex}"
  database_version = "MYSQL_5_7"
  region           = var.network_region
  project          = google_project.demo_project.project_id

  settings {
    tier                  = "db-g1-small"
    disk_autoresize       = true
    disk_autoresize_limit = 0
    disk_size             = 10
    disk_type             = "PD_SSD"
    user_labels           = var.app-labels
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.host_network.self_link
    }
    location_preference {
      zone = var.network_zone
    }
  }
  deletion_protection = false
  depends_on = [
    time_sleep.wait_120_seconds_enable_service_api,
    google_vpc_access_connector.main,
  ]
}


resource "google_sql_database" "database" {
  project  = google_project.demo_project.project_id
  name     = "todo"
  instance = google_sql_database_instance.main.name
}

# Create a random password for the DB and to store in secret manager
resource "random_password" "password" {
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# Creating the user and password in the DB instance
resource "google_sql_user" "main" {
  project  = google_project.demo_project.project_id
  name     = "todo_user"
  password = random_password.password.result
  instance = google_sql_database_instance.main.name
}

# Redis instance creation
resource "google_redis_instance" "main" {
  authorized_network      = google_compute_network.host_network.self_link
  connect_mode            = "DIRECT_PEERING"
  location_id             = var.network_zone
  memory_size_gb          = 1
  name                    = "${var.deployment_name}-cache"
  project                 = google_project.demo_project.project_id
  redis_version           = "REDIS_6_X"
  region                  = var.network_region
  reserved_ip_range       = "10.137.125.88/29"
  tier                    = "BASIC"
  transit_encryption_mode = "DISABLED"
  depends_on              = [time_sleep.wait_120_seconds_enable_service_api]
  labels                  = var.app-labels
}


# Pushing secrets in secret manager
module "secret-manager" {
  source     = "GoogleCloudPlatform/secret-manager/google"
  version    = "~> 0.1"
  project_id = google_project.demo_project.project_id
  labels = {
    redishost = var.app-labels,
    sqlhost   = var.app-labels,
    todo_user = var.app-labels,
    todo_pass = var.app-labels
  }
  secrets = [
    {
      name                  = "redishost"
      automatic_replication = true
      secret_data           = google_redis_instance.main.host
    },
    {
      name                  = "sqlhost"
      automatic_replication = true
      secret_data           = google_sql_database_instance.main.ip_address.0.ip_address
    },
    {
      name                  = "todo_user"
      automatic_replication = true
      secret_data           = "todo_user"
    },
    {
      name                  = "todo_pass"
      automatic_replication = true
      secret_data           = google_sql_user.main.password
    },
  ]
}

# Creating the Cloud Run instance for the applilcaiton API
 resource "google_cloud_run_service" "api" {
  name     = "${var.deployment_name}-api"
  provider = google-beta
  location = var.network_region
  project  = google_project.demo_project.project_id


  template {
    spec {
      service_account_name = google_service_account.runsa.email
      containers {
        image = local.api_image
        env {
         name = "REDISHOST"
          value_from {
            secret_key_ref {
              name = "redishost"
              key  = "latest"
            }
          }
        }
        env {
          name = "todo_host"
         value_from {
            secret_key_ref {
              name = "sqlhost"
              key  = "latest"
            }
          }
        }

        env {
          name = "todo_user"
          value_from {
            secret_key_ref {
              name = "todo_user"
              key  = "latest"
            }
          }
        }

        env {
          name = "todo_pass"
          value_from {
            secret_key_ref {
              name = "todo_pass"
              key  = "latest"
            }
          }
        }
        env {
          name  = "todo_name"
          value = "todo"
       }

        env {
          name  = "REDISPORT"
          value = "6379"
        }

      }
    }

    metadata {
      annotations = {
        "autoscaling.knative.dev/maxScale"        = "1000"
        "run.googleapis.com/cloudsql-instances"   = google_sql_database_instance.main.connection_name
        "run.googleapis.com/client-name"          = "terraform"
        "run.googleapis.com/vpc-access-egress"    = "all"
        "run.googleapis.com/vpc-access-connector" = google_vpc_access_connector.main.id

      }
    }
  }
  metadata {
    labels = var.app-labels
  }
  autogenerate_revision_name = true
  depends_on = [
    google_project_iam_member.allrun,
    module.secret-manager
  ]
}


# Creating the Cloud Run instance for the applilcaiton 
resource "google_cloud_run_service" "fe" {
  name     = "${var.deployment_name}-fe"
  location = var.network_region
  project  = google_project.demo_project.project_id

  template {
    spec {
      service_account_name = google_service_account.runsa.email
      containers {
        image = local.fe_image
        
        ports {
          container_port = 80
        }
        env {
          name  = "ENDPOINT"
          value = google_cloud_run_service.api.status[0].url
        }
      }
    }
  }
  metadata {
    labels = var.app-labels
  }
}

# Setting up the IAM access for Cloud Run API instance
resource "google_cloud_run_service_iam_member" "noauth_api" {
  location = google_cloud_run_service.api.location
  project  = google_cloud_run_service.api.project
  service  = google_cloud_run_service.api.name
  role     = "roles/run.invoker"
 
#  member   = "allUsers" # enable if you wish to see the URL access in browser and comment the below member def and depends on, also update the below IAM policy constraint
#  depends_on = [google_project_organization_policy.domain_restricted_sharing]
  member = var.proxy_access_identities  
}

# Setting up the IAM access for Cloud Run Application instance
resource "google_cloud_run_service_iam_member" "noauth_fe" {
  location = google_cloud_run_service.fe.location
  project  = google_cloud_run_service.fe.project
  service  = google_cloud_run_service.fe.name
  role     = "roles/run.invoker"
    
# member   = "allUsers" # enable if you wish to see the URL access in browser and uncomment the below member def and depends on, also update the below IAM policy constraint
#  depends_on = [google_project_organization_policy.domain_restricted_sharing]
member = var.proxy_access_identities
}



#Setting up the IAM policy constraint. If the IAM access for api & application is set for all users then uncomment the constraint.
#resource "google_project_organization_policy" "domain_restricted_sharing" {
#  project = google_project.demo_project.project_id
#  constraint = "constraints/iam.allowedPolicyMemberDomains"
#  list_policy {
#    allow {
#      all = true 
#    }
#  }
#    depends_on = [time_sleep.wait_120_seconds_enable_service_api]
#}
