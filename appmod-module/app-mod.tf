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



# Create the Appmod Project
resource "google_project" "appmod_project" {
  project_id      = "${var.demo_project_id}${var.appmodtag}${var.random_string}"
  name            = "SF Solution - App Mod"
  billing_account = var.billing_account
  folder_id = var.folder_id
  }



module "project_services" {
  source  = "terraform-google-modules/project-factory/google//modules/project_services"
  version = "13.0.0"

  
  activate_apis = [
    "cloudapis.googleapis.com",
    "vpcaccess.googleapis.com",
    "servicenetworking.googleapis.com",
    "cloudbuild.googleapis.com",
    "monitoring.googleapis.com",
    "sql-component.googleapis.com",
    "sqladmin.googleapis.com",
    "storage.googleapis.com",
    "secretmanager.googleapis.com",
    "run.googleapis.com",
    "redis.googleapis.com",
    "clouddebugger.googleapis.com",
    "cloudprofiler.googleapis.com",
    "cloudbuild.googleapis.com",
    "binaryauthorization.googleapis.com",
    "containersecurity.googleapis.com",
    "compute.googleapis.com",
    "containerscanning.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudkms.googleapis.com",
    "container.googleapis.com",
    "cloudtrace.googleapis.com",

  ]
   project_id        = google_project.appmod_project.project_id
  disable_services_on_destroy	= true
  disable_dependent_services = true
  depends_on = [google_project.appmod_project]
}



# wait delay after enabling APIs
resource "time_sleep" "wait_120_seconds_enable_service_api_appmod" {
  depends_on = [module.project_services]
  create_duration = "120s"
  destroy_duration = "120s"
}


#Create the service Account
resource "google_service_account" "sql_ser_acc" {
   project = google_project.appmod_project.project_id
   account_id   = "sa-service-account"
   display_name = "CLoud SQL Service Account"
   depends_on = [time_sleep.wait_120_seconds_enable_service_api_appmod]
 }


data "google_project" "appmod_project" {
  project_id = google_project.appmod_project.project_id
  depends_on = [time_sleep.wait_120_seconds_enable_service_api_appmod]
}

locals {

 # Cloud Run locals
  sabuild   = "${data.google_project.appmod_project.number}@cloudbuild.gserviceaccount.com"
  api_image = "gcr.io/sic-container-repo/todo-api"
  fe_image  = "gcr.io/sic-container-repo/todo-fe"

   #GKE-Cluster locals
  memorystore_apis = ["redis.googleapis.com"]
  cluster_id_parts = split("/", google_container_cluster.my_cluster.id)
  cluster_name = element(local.cluster_id_parts, length(local.cluster_id_parts) - 1)
   
}


#Cloud Run service account
resource "google_service_account" "runsa" {
  project      = google_project.appmod_project.project_id
  account_id   = "${var.deployment_name}-run-sa"
  display_name = "Service Account for Cloud Run"
  depends_on = [time_sleep.wait_120_seconds_enable_service_api_appmod]
}


# IAM provilige assigned to Cloud Run SA to accessess secrets
resource "google_project_iam_member" "allrun" {
  project    = data.google_project.appmod_project.number
  role       = "roles/secretmanager.secretAccessor"
  member     = "serviceAccount:${google_service_account.runsa.email}"
  depends_on = [time_sleep.wait_120_seconds_enable_service_api_appmod]
}



# Create the host network
resource "google_compute_network" "host_network" {
  project                 = google_project.appmod_project.project_id
  name                    = var.vpc_network_name
  auto_create_subnetworks = false
  description             = "Host network for the Cloud SQL instance and proxy"
  depends_on = [time_sleep.wait_120_seconds_enable_service_api_appmod]
}

# Create  Subnetwork
resource "google_compute_subnetwork" "sql_subnetwork" {
  name          = "host-network-${var.network_region}"
  ip_cidr_range = "192.168.0.0/16"
  region        = var.network_region
  project = google_project.appmod_project.project_id
  network       = google_compute_network.host_network.self_link
 
  # Enabling VPC flow logs
 log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
  private_ip_google_access   = true 
  depends_on = [
    google_compute_network.host_network,
    time_sleep.wait_120_seconds_enable_service_api_appmod,
  ]
}


# Setup Private IP access
resource "google_compute_global_address" "sql_instance_private_ip" {
  name          = "sql-private-address"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  address       = "10.10.10.0"
  prefix_length = 24
  network       = google_compute_network.host_network.id
  project = google_project.appmod_project.project_id
  description = "Cloud SQL IP Range"
  depends_on = [
   time_sleep.wait_120_seconds_enable_service_api_appmod,
    google_compute_subnetwork.sql_subnetwork,
    ]  
}

# Create Private Connection:
resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.host_network.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.sql_instance_private_ip.name]
  depends_on = [
    google_compute_global_address.sql_instance_private_ip,
    ]
}



# Create the VPC connector for Cloud Run access to VPC network
resource "google_vpc_access_connector" "main" {
  provider       = google-beta
  project        = google_project.appmod_project.project_id
  name           = "${var.deployment_name}-vpc-cx"
  ip_cidr_range  = "10.8.0.0/28"
  network        = google_compute_network.host_network.self_link
  region         = var.network_region
  max_throughput = 300
  depends_on     = [google_compute_global_address.sql_instance_private_ip]
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
  project          = google_project.appmod_project.project_id

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
    time_sleep.wait_120_seconds_enable_service_api_appmod,
    google_vpc_access_connector.main,
  ]
}

resource "google_sql_database" "database" {
  project  = google_project.appmod_project.project_id
  name     = "todo"
  instance = google_sql_database_instance.main.name
  depends_on = [time_sleep.wait_120_seconds_enable_service_api_appmod]
}


# Create a random password for the DB and to store in secret manager
resource "random_password" "password" {
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
  depends_on = [time_sleep.wait_120_seconds_enable_service_api_appmod]
}


# Creating the user and password in the DB instance
resource "google_sql_user" "main" {
  project  = google_project.appmod_project.project_id
  name     = "todo_user"
  password = random_password.password.result
  instance = google_sql_database_instance.main.name
  depends_on = [
    time_sleep.wait_120_seconds_enable_service_api_appmod,
    google_redis_instance.main,
    ]
}


# Redis instance creation
resource "google_redis_instance" "main" {
  authorized_network      = google_compute_network.host_network.self_link
  connect_mode            = "DIRECT_PEERING"
  location_id             = var.network_zone
  memory_size_gb          = 1
  name                    = "${var.deployment_name}-cache"
  project                 = google_project.appmod_project.project_id
  redis_version           = "REDIS_6_X"
  region                  = var.network_region
  reserved_ip_range       = "10.137.125.88/29"
  tier                    = "BASIC"
  transit_encryption_mode = "DISABLED"
  labels                  = var.app-labels
  depends_on = [
    time_sleep.wait_120_seconds_enable_service_api_appmod,
    ]
}



# Pushing secrets in secret manager
module "secret-manager" {
  source     = "GoogleCloudPlatform/secret-manager/google"
  version    = "~> 0.1"
  project_id = google_project.appmod_project.project_id
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
  depends_on = [
    time_sleep.wait_120_seconds_enable_service_api_appmod,
    google_sql_database_instance.main,
    ]
}


# Creating the Cloud Run instance for the applilcaiton API
 resource "google_cloud_run_service" "api" {
  name     = "${var.deployment_name}-api"
  provider = google-beta
  location = var.network_region
  project  = google_project.appmod_project.project_id


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
    module.secret-manager,
    time_sleep.wait_120_seconds_enable_service_api_appmod,
  ]
}



# Creating the Cloud Run instance for the applilcaiton 
resource "google_cloud_run_service" "fe" {
  name     = "${var.deployment_name}-fe"
  location = var.network_region
  project  = google_project.appmod_project.project_id

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
  depends_on = [
    time_sleep.wait_120_seconds_enable_service_api_appmod,
    google_cloud_run_service.api,
    ]
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

resource "google_cloud_run_service_iam_member" "noauth_fe" {
  location = google_cloud_run_service.fe.location
  project  = google_cloud_run_service.fe.project
  service  = google_cloud_run_service.fe.name
  role     = "roles/run.invoker"

#  member   = "allUsers" # enable if you wish to see the URL access in browser and comment the below member def and depends on, also update the below IAM policy constraint
#  depends_on = [google_project_organization_policy.domain_restricted_sharing]
  member = var.proxy_access_identities 
}

#Setting up the IAM policy constraint. If the IAM access for api & application is set for all users then uncomment the constraint.
#resource "google_project_organization_policy" "domain_restricted_sharing" {
#  project = google_project.appmod_project.project_id
#  constraint = "constraints/iam.allowedPolicyMemberDomains"
#  list_policy {
#    allow {
#      all = true
#    }
#  }
#  depends_on = [time_sleep.wait_120_seconds_enable_service_api_appmod]
#}


 
# gke-cluster demo https://github.com/GoogleCloudPlatform/microservices-demo
resource "google_binary_authorization_policy" "this" {
#  description                   = var.description
  global_policy_evaluation_mode = var.global_policy_evaluation_mode
  project                       = google_project.appmod_project.project_id
        
    default_admission_rule {   
      enforcement_mode        = var.enforcement_mode
      evaluation_mode         = var.evaluation_mode
 }
    admission_whitelist_patterns {
      name_pattern  = "gcr.io/google-samples/microservices-demo/emailservice:v0.3.9"
    }
    admission_whitelist_patterns {
      name_pattern  = "gcr.io/google-samples/microservices-demo/checkoutservice:v0.3.9"
    }
    depends_on = [
    time_sleep.wait_120_seconds_enable_service_api_appmod,
      ]

}



# Create the Memorystore (redis) instance
resource "google_redis_instance" "redis-cart" {
  name           = "redis-cart"
  memory_size_gb = 1
  region         = var.network_region
  # count specifies the number of instances to create;
  # if var.memorystore is true then the resource is enabled
  count          = var.memorystore ? 1 : 0

  redis_version  = "REDIS_6_X"
  project        = google_project.appmod_project.project_id

  depends_on = [
    time_sleep.wait_120_seconds_enable_service_api_appmod,
  ]
}

# Edit contents of Memorystore kustomization.yaml file to target new Memorystore (redis) instance
resource "null_resource" "kustomization-update" {
  provisioner "local-exec" {
    interpreter = ["bash", "-exc"]
    command     = "sed -i \"s/REDIS_IP/${google_redis_instance.redis-cart[0].host}/g\" ../kustomize/components/memorystore/kustomization.yaml"
  }

  # count specifies the number of instances to create;
  # if var.memorystore is true then the resource is enabled
  count          = var.memorystore ? 1 : 0

  depends_on = [
    resource.google_redis_instance.redis-cart
  ]
}



# Creating GKE network
resource "google_compute_network" "cloud_gke_network" {
  project                 = google_project.appmod_project.project_id
  name                    = "gke-network"
  auto_create_subnetworks = false
  depends_on = [
    google_binary_authorization_policy.this,
    ]
}

# Creating GKE sub network
resource "google_compute_subnetwork" "cloud_gke_subnetwork" {
  name          = "cloud-gke-${var.network_region}"
  ip_cidr_range = "192.168.10.0/24"
  region        = var.network_region
  project = google_project.appmod_project.project_id
  network       = google_compute_network.cloud_gke_network.self_link
  private_ip_google_access   = true 
  depends_on = [
    google_compute_network.cloud_gke_network,
  ]
}



# Create a CloudRouter
resource "google_compute_router" "router" {
  project = google_project.appmod_project.project_id
  name    = "subnet-router"
  region  = google_compute_subnetwork.cloud_gke_subnetwork.region
  network = google_compute_network.cloud_gke_network.id

  bgp {
    asn = 64514
  }
}
 
# Configure a CloudNAT
resource "google_compute_router_nat" "nats" {
  project = google_project.appmod_project.project_id
  name                               = "nat-cloud-sql-${var.vpc_network_name}"
  router                             = google_compute_router.router.name
  region                             = google_compute_router.router.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
  depends_on = [google_compute_router.router]
}


resource "google_compute_firewall" "allow_http_icmp" {
name = "allow-http-icmp"
network = google_compute_network.cloud_gke_network.self_link
project = google_project.appmod_project.project_id
direction = "INGRESS"
allow {
    protocol = "tcp"
    ports    = ["22"]
    }
 source_ranges = ["0.0.0.0/0"]
#target_service_accounts = [
 #   google_service_account.def_ser_acc.email
#  ]
allow {
    protocol = "icmp"
    }
    depends_on = [
        google_compute_network.cloud_gke_network
    ]
} 



/* 
# Enable this if external IP access is needed 
resource "google_project_organization_policy" "external_ip_access" {
  project = google_project.appmod_project.project_id
  constraint = "constraints/compute.vmExternalIpAccess"
  list_policy {
    allow {
      all = true
    }
  }
  depends_on = [
    time_sleep.wait_120_seconds_enable_service_api_appmod,
    ]
}
*/


# Create GKE cluster
resource "google_container_cluster" "my_cluster" {
  name     = var.name
  location = var.network_region
  project  = google_project.appmod_project.project_id
  # Enabling autopilot for this cluster
  enable_autopilot = true
  binary_authorization {
  evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }
  network       = google_compute_network.cloud_gke_network.self_link
  subnetwork = google_compute_subnetwork.cloud_gke_subnetwork.self_link
  # Setting an empty ip_allocation_policy to allow autopilot cluster to spin up correctly
  
/* remove_default_node_pool = false
  initial_node_count       = 2

addons_config {
    http_load_balancing {
      disabled = false
    }
    horizontal_pod_autoscaling {
      disabled = true
    }
  }

  release_channel {
    channel = "REGULAR"
  }

    node_config {
    preemptible  = false
    machine_type = "e2-medium"
    
    labels = {
      role = "general"
    }
    }
*/
    ip_allocation_policy {
#    cluster_secondary_range_name  = "gke-pods"
    cluster_ipv4_cidr_block       = "10.4.0.0/14"
#    services_secondary_range_name = "gke-svc"
    services_ipv4_cidr_block      = "10.8.0.0/20"
   }

  
    private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = true
#    master_ipv4_cidr_block  = "172.168.236.224/28"
    }

     master_authorized_networks_config {
        cidr_blocks {
        cidr_block   = "192.168.10.0/24"
        display_name = "internal"
      }
}  

  depends_on = [
    google_binary_authorization_policy.this,
#    google_project_organization_policy.external_ip_access,
    ]
}


#Create the service Account
resource "google_service_account" "k8_ser_acc" {
   project = google_project.appmod_project.project_id
   account_id   = "k8-service-account"
   display_name = "Kubernetes Proxy Service Account"
   depends_on = [
    time_sleep.wait_120_seconds_enable_service_api_appmod,
    ]
 }


resource "google_organization_iam_member" "k8_proj_owner" {
    org_id  = var.organization_id
    role    = "roles/owner"
    member  = "serviceAccount:${google_service_account.k8_ser_acc.email}"
    depends_on = [google_service_account.k8_ser_acc]
    }

resource "google_organization_iam_member" "k8_container_admin" {
    org_id  = var.organization_id
    role    = "roles/container.admin"
    member  = "serviceAccount:${google_service_account.k8_ser_acc.email}"
    depends_on = [google_organization_iam_member.k8_proj_owner]
    }

resource "google_organization_iam_member" "k8_container_dev" {
    org_id  = var.organization_id
    role    = "roles/container.developer"
    member  = "serviceAccount:${google_service_account.k8_ser_acc.email}"
    depends_on = [google_organization_iam_member.k8_proj_owner]
    }



# Create Compute Instance (debian)
resource "google_compute_instance" "kubernetes_proxy_server1" {
    project      = google_project.appmod_project.project_id
    name         = "kubernetes-proxy-server"
    machine_type = "n2-standard-4"
    zone         = var.network_zone

    shielded_instance_config {
        enable_integrity_monitoring = true
        enable_secure_boot          = true
        enable_vtpm                 = true
    }

  depends_on = [
    time_sleep.wait_120_seconds_enable_service_api_appmod,
    google_organization_iam_member.k8_proj_owner,
    google_container_cluster.my_cluster,
    google_compute_router_nat.nats,
    ]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-10"
    }
 }

  network_interface {
  network       = google_compute_network.cloud_gke_network.self_link
  subnetwork = google_compute_subnetwork.cloud_gke_subnetwork.self_link
   
  }

  service_account {
    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    email                       = google_service_account.k8_ser_acc.email
    scopes                      = ["cloud-platform"]
  }
    metadata_startup_script     = "sudo apt-get update -y;sudo apt-get install git -y;sudo apt-get install kubectl;sudo apt-get install google-cloud-sdk-gke-gcloud-auth-plugin;git clone https://github.com/mgaur10/security-foundation-bundle-.git;sudo gcloud container clusters get-credentials ${local.cluster_name} --zone=us-east1 --project=${var.demo_project_id}${var.appmodtag}${var.random_string};sudo kubectl apply -f /security-foundation-bundle-/appmod-module/release/kubernetes-manifests.yaml;"
    

    labels =   {
        asset_type = "prod"
        osshortname = "debian"  
        }
}







/* 

# Get credentials for cluster
module "gcloud" {
  source  = "terraform-google-modules/gcloud/google"
  version = "~> 2.0"

  platform              = "linux"
  additional_components = ["kubectl", "beta"]

  create_cmd_entrypoint = "gcloud"
  # Use local variable cluster_name for an implicit dependency on resource "google_container_cluster" 
  create_cmd_body = "container clusters get-credentials ${local.cluster_name} --zone=${var.network_region} --project=${var.demo_project_id}${var.appmodtag}${var.random_string}"
 }

# Apply YAML kubernetes-manifest configurations
resource "null_resource" "apply_deployment" {
  provisioner "local-exec" {
    interpreter = ["bash", "-exc"]
    command     = "kubectl apply -f ${var.filepath_manifest}"
  }

    depends_on = [
    module.gcloud,
    google_binary_authorization_policy.this,
#   google_project_organization_policy.external_ip_access,
    ]
}

# Wait condition for all Pods to be ready before finishing
resource "null_resource" "wait_conditions" {
  provisioner "local-exec" {
    interpreter = ["bash", "-exc"]
    command     = "kubectl wait --for=condition=ready pods --all -n ${var.namespace} --timeout=-1s"
  }

  depends_on = [
    resource.null_resource.apply_deployment
  ]
}
  */



/* 
# NGINX Image push to container registry
resource "null_resource" "image_push" {
  provisioner "local-exec" {
  #  interpreter = ["bash", "-exc"]
    command     = <<EOT
    docker pull gcr.io/google-containers/nginx:latest
    docker tag gcr.io/google-containers/nginx "gcr.io/${var.demo_project_id}${var.appmodtag}${var.random_string}/nginx:latest"
    docker push "gcr.io/${var.demo_project_id}${var.appmodtag}${var.random_string}/nginx:latest"
    EOT
  }

  depends_on = [
     time_sleep.wait_120_seconds_enable_service_api_appmod,
  ]
}

# UBUNTU image push to container registry
resource "null_resource" "image_push_ubuntu" {
  provisioner "local-exec" {
  #  interpreter = ["bash", "-exc"]
    command     = <<EOT
    docker pull gcr.io/google-containers/ubuntu@sha256:5746b3b4974d1bd3d4ddbac0373fb71b425f13583797414ffd9d8b547d241f75
    docker tag gcr.io/google-containers/ubuntu@sha256:5746b3b4974d1bd3d4ddbac0373fb71b425f13583797414ffd9d8b547d241f75 "gcr.io/${var.demo_project_id}${var.appmodtag}${var.random_string}/ubuntu:latest"
    docker push "gcr.io/${var.demo_project_id}${var.appmodtag}${var.random_string}/ubuntu:latest"
    EOT
  }

  depends_on = [
     time_sleep.wait_120_seconds_enable_service_api_appmod,
  ]
}

# Debian image push to container registry
resource "null_resource" "image_push_debian" {
  provisioner "local-exec" {
  #  interpreter = ["bash", "-exc"]
    command     = <<EOT
    docker pull gcr.io/google-containers/debian-base@sha256:3a6ec824717e1ca5bb136ffa3dfbd854f109a0b2b376dd2cf9701d4669778fd2
    docker tag gcr.io/google-containers/debian-base@sha256:3a6ec824717e1ca5bb136ffa3dfbd854f109a0b2b376dd2cf9701d4669778fd2 "gcr.io/${var.demo_project_id}${var.appmodtag}${var.random_string}/debian:latest"
    docker push "gcr.io/${var.demo_project_id}${var.appmodtag}${var.random_string}/debian:latest"
    EOT
  }

  depends_on = [
     time_sleep.wait_120_seconds_enable_service_api_appmod,
  ]
}
 */


# Create a kms key ring and key
      resource "google_kms_key_ring" "keyring" {
    project = google_project.appmod_project.project_id
    name     = var.keyring_name
    location = var.network_region
    depends_on = [time_sleep.wait_120_seconds_enable_service_api_appmod]
  } 
  
  resource "google_kms_crypto_key" "kms-key" {
    name            = var.crypto_key_name
    key_ring        = google_kms_key_ring.keyring.id
    rotation_period = "100000s"

    lifecycle {
      prevent_destroy = false
    }
    depends_on = [google_kms_key_ring.keyring]
  }  





# Create an artifact registry repo
resource "google_artifact_registry_repository" "artifact_repo" {
  project = google_project.appmod_project.project_id 

  location      = var.network_region
  repository_id = "artifact-repository"
  description   = "Artifact docker repository with cmek"
  format        = "DOCKER"
  kms_key_name  = "projects/${var.demo_project_id}${var.appmodtag}${var.random_string}/locations/${var.network_region}/keyRings/${var.keyring_name}/cryptoKeys/${var.crypto_key_name}"
  
depends_on = [
     time_sleep.wait_120_seconds_enable_service_api_appmod,
     google_project_iam_member.art_reg_agent,
     google_project_iam_member.kms_art_reg_agent
  ]
}

# Create a service identity for Artifact registry
resource "google_project_service_identity" "art_reg" {
  provider = google-beta

  project = google_project.appmod_project.project_id
  service = "artifactregistry.googleapis.com"

  depends_on = [time_sleep.wait_120_seconds_enable_service_api_appmod]
}

# Assign service agent role to Artifact registry service account
resource "google_project_iam_member" "art_reg_agent" {
  project = google_project.appmod_project.project_id
  role    = "roles/artifactregistry.serviceAgent"
  member  = "serviceAccount:${google_project_service_identity.art_reg.email}"

  depends_on = [google_project_service_identity.art_reg]
}

# Assign KMS role agent role to Artifact registry service account
resource "google_project_iam_member" "kms_art_reg_agent" {
  project = google_project.appmod_project.project_id
  role    = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member  = "serviceAccount:${google_project_service_identity.art_reg.email}"
    depends_on = [google_project_service_identity.art_reg]
}

# Assign artifiact registry admin role to Artifact registry service account
resource "google_artifact_registry_repository_iam_member" "repo_admin" {
  project = google_project.appmod_project.project_id 
  location = var.network_region
  repository = google_artifact_registry_repository.artifact_repo.name
  role = "roles/artifactregistry.admin"
  member = var.proxy_access_identities

depends_on = [
     google_artifact_registry_repository.artifact_repo,
  ]
}


# Debian image push to artifact registry repo
resource "null_resource" "artifact_push_debian" {
  provisioner "local-exec" {
  #  interpreter = ["bash", "-exc"]
    command     = <<EOT
    gcloud auth configure-docker ${var.network_region}-docker.pkg.dev
    docker pull gcr.io/google-containers/debian-base@sha256:3a6ec824717e1ca5bb136ffa3dfbd854f109a0b2b376dd2cf9701d4669778fd2
    docker tag gcr.io/google-containers/debian-base@sha256:3a6ec824717e1ca5bb136ffa3dfbd854f109a0b2b376dd2cf9701d4669778fd2 ${var.network_region}-docker.pkg.dev/${var.demo_project_id}${var.appmodtag}${var.random_string}/artifact-repository/debian
    docker push ${var.network_region}-docker.pkg.dev/${var.demo_project_id}${var.appmodtag}${var.random_string}/artifact-repository/debian
       EOT
  }
  depends_on = [
    google_artifact_registry_repository_iam_member.repo_admin,
   ]
}


# NGNIX image push to artifact registry repo
resource "null_resource" "artifact_push_nginx" {
  provisioner "local-exec" {
#  #  interpreter = ["bash", "-exc"]
    command     = <<EOT
     docker pull gcr.io/google-containers/nginx:latest
    docker tag gcr.io/google-containers/nginx:latest ${var.network_region}-docker.pkg.dev/${var.demo_project_id}${var.appmodtag}${var.random_string}/artifact-repository/nginx
    docker push ${var.network_region}-docker.pkg.dev/${var.demo_project_id}${var.appmodtag}${var.random_string}/artifact-repository/nginx
    EOT
  }
  depends_on = [
    google_artifact_registry_repository_iam_member.repo_admin,
    resource.null_resource.artifact_push_debian,
  ]
}