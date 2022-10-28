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



# Random id for naming
resource "random_string" "id" {
    length  = 4
    upper   = false
    lower   = true
    number  = true
    special = false
    }


# Create Folder in GCP Organization
resource "google_folder" "terraform_solution" {
    display_name    =  "${var.folder_name}${random_string.id.result}"
    parent          = "organizations/${var.organization_id}"
  }

data "google_active_folder" "sf_folder" {
    display_name    =  "${var.folder_name}${random_string.id.result}"
    parent          = "organizations/${var.organization_id}"
    depends_on              = [google_folder.terraform_solution]
}

# Enabling logging at Folder level
  resource "google_folder_iam_audit_config" "config_data_log" {
  folder = data.google_active_folder.sf_folder.id
  service = "allServices"
  audit_log_config {
    log_type = "ADMIN_READ"
 #   exempted_members = [
#      "user:joebloggs@hashicorp.com",
#    ]
  }

  audit_log_config {
    log_type = "DATA_READ"
 #   exempted_members = [
#      "user:joebloggs@hashicorp.com",
#    ]
  }

  depends_on              = [data.google_active_folder.sf_folder]
}



# Create the Project
resource "google_project" "demo_project" {
    project_id      = "${var.demo_project_id}${random_string.id.result}"
    name            = "SF Solution - InfraMod"
    billing_account = var.billing_account
    folder_id       = google_folder.terraform_solution.name
    depends_on      = [
        google_folder.terraform_solution
  ]
}



module "project_services_core" {
  source  = "terraform-google-modules/project-factory/google//modules/project_services"
  version = "13.0.0"

  
  activate_apis = [
    "sqladmin.googleapis.com",
    "servicenetworking.googleapis.com",
    "logging.googleapis.com",
    "secretmanager.googleapis.com",
    "iap.googleapis.com",
    "cloudkms.googleapis.com",
    "iam.googleapis.com",
    "osconfig.googleapis.com",
    "containeranalysis.googleapis.com",
    "cloudapis.googleapis.com",
    "vpcaccess.googleapis.com",
    "cloudbuild.googleapis.com",
    "sql-component.googleapis.com",
    "storage.googleapis.com",
    "run.googleapis.com",
    "redis.googleapis.com",   
    "compute.googleapis.com",

  ]
   project_id        = google_project.demo_project.project_id
  disable_services_on_destroy	= true
  disable_dependent_services = true
  depends_on = [google_project.demo_project]
}
# wait delay after enabling APIs
resource "time_sleep" "wait_120_seconds_enable_service_api" {
    depends_on          = [module.project_services_core]
 #   google_project_service.api_service]
    create_duration     = "120s"
    destroy_duration    = "120s"
}

/* Remove the comments to implement IDS module
module "ids_deploy" {
    source                  = "./ids-module"
    folder_id               = google_folder.terraform_solution.name
    demo_project_id         = var.demo_project_id
    vpc_network_name        = var.vpc_network_name
    network_region          = var.network_region
    network_zone            = var. network_zone
    random_string           = random_string.id.result
    idstag                  = "ids-"
    billing_account         = var.billing_account
    proxy_access_identities = var.proxy_access_identities
}

*/

module "appmod_deploy" {
    source                      = "./appmod-module"
    folder_id                   = google_folder.terraform_solution.name
    organization_id                 = var.organization_id
    demo_project_id             = var.demo_project_id
    vpc_network_name            = var.vpc_network_name
    network_region              = var.network_region
    network_zone                = var. network_zone
    random_string               = random_string.id.result
    appmodtag                   = "appmod-"
    billing_account             = var.billing_account
    proxy_access_identities     = var.proxy_access_identities
    deployment_name             = var.deployment_name
    app-labels                  = var.app-labels
    keyring_name                = var.keyring_name 
    crypto_key_name             = var.crypto_key_name
    memorystore                 = false
}


module "dlp_deploy" {
    source = "./dlp-vpcsc-module"
    folder_id                       = google_folder.terraform_solution.name
    demo_project_id                 = var.demo_project_id
    organization_id                 = var.organization_id
    network_region                  = var.network_region
    network_zone                    = var. network_zone
    random_string                   = random_string.id.result
    dlptag                          = "dlp-"
    vpcsctag                        = "vpc-sc-"
    billing_account                 = var.billing_account
    qa_storage_bucket_name          = "dlp-demo-qa-"
    sens_storage_bucket_name        = "dlp-demo-sens-"
    nonsens_storage_bucket_name     = "dlp-demo-nonsens-"
    pubsub_topic_name               = "dlp-demo-pubsub"
    pubsub_subscription_name        = "dlp-demo-pubsub-topic"
    proxy_access_identities         = var.proxy_access_identities
    create_default_access_policy    = false
}





# Create the host network

resource "google_compute_network" "host_network" {
    project                 = google_project.demo_project.project_id
    name                    = var.vpc_network_name
    auto_create_subnetworks = false
    description             = "Host network for the Cloud SQL instance and proxy"
    depends_on              = [time_sleep.wait_120_seconds_enable_service_api]
}

# Create SQL Subnetwork

resource "google_compute_subnetwork" "sql_subnetwork" {
    name          = "host-network-${var.network_region}"
    ip_cidr_range = "192.168.0.0/16"
    region        = var.network_region
    project       = google_project.demo_project.project_id
    network       = google_compute_network.host_network.self_link
    # Enabling VPC flow logs
    log_config {
        aggregation_interval = "INTERVAL_10_MIN"
        flow_sampling        = 0.5
        metadata             = "INCLUDE_ALL_METADATA"
  }
    private_ip_google_access = true 
    depends_on               = [
        google_compute_network.host_network,
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
    project       = google_project.demo_project.project_id
    description   = "Cloud SQL IP Range"
    depends_on    = [time_sleep.wait_120_seconds_enable_service_api]  
}


# Create Private Connection:
resource "google_service_networking_connection" "private_vpc_connection" {
    network                 = google_compute_network.host_network.id
    service                 = "servicenetworking.googleapis.com"
    reserved_peering_ranges = [google_compute_global_address.sql_instance_private_ip.name]
    depends_on              = [
        time_sleep.wait_120_seconds_enable_service_api,
        google_compute_global_address.sql_instance_private_ip,
        ]
}


# Create Proxy Server Instance (debian)
resource "google_compute_instance" "debian_server" {
    project      = google_project.demo_project.project_id
    name         = "proxy-server"
    machine_type = "n2-standard-4"
    zone         = var.network_zone

    shielded_instance_config {
        enable_integrity_monitoring = true
        enable_secure_boot          = true
        enable_vtpm                 = true
    }

  depends_on = [
    time_sleep.wait_120_seconds_enable_service_api,
    google_compute_router_nat.nats,
    ]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-10"
    }
 }

  network_interface {
    network         = google_compute_network.host_network.self_link
    subnetwork      = google_compute_subnetwork.sql_subnetwork.self_link
   
  }

  service_account {
    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    email                       = google_service_account.def_ser_acc.email
    scopes                      = ["cloud-platform"]
  }
   metadata_startup_script     = "sudo apt-get update -y;sudo apt-get install -y git;git clone https://github.com/mgaur10/security-foundation-solution.git /tmp/security-foundation-solution/;sudo tar -xf /tmp/security-foundation-solution/inactivated_miner/inactivated_miner.tar;sudo chmod 777 inactivated_miner;sudo ./inactivated_miner;"

    
    labels =   {
        asset_type = "prod"
        osshortname = "debian"  
        }
}

# Create Compute Instance Ubuntu
resource "google_compute_instance" "ubuntu_server" {
    project         = google_project.demo_project.project_id
    name            = "ubuntu-server"
    machine_type    = "n2-standard-2"
    zone            = var.network_zone

    shielded_instance_config {
        enable_integrity_monitoring = true
        enable_secure_boot          = true
        enable_vtpm                 = true
        }

  depends_on = [
    time_sleep.wait_120_seconds_enable_service_api,
    google_compute_router_nat.nats,
        ]

    boot_disk {
    initialize_params {
        image       = "ubuntu-os-cloud/ubuntu-2004-lts-arm64"
    }
 }

    network_interface {
    network     = google_compute_network.host_network.self_link
    subnetwork  = google_compute_subnetwork.sql_subnetwork.self_link
   
  }

  service_account {
    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    email  = google_service_account.def_ser_acc.email
    scopes = ["cloud-platform"]
  }

  metadata_startup_script = "sudo apt-get update -y;sudo apt-get install -y wget curl;curl etd-malware-trigger.goog"

 labels =  {
  asset_type = "prod"
  osshortname = "ubuntu"
  label = "ubuntu"
}
}

# Create Compute Instance RHEL
resource "google_compute_instance" "rhel_server" {
  project = google_project.demo_project.project_id
  name         = "rhel-server"
  machine_type = "n2-standard-2"
  zone         = var.network_zone

  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_secure_boot          = true
    enable_vtpm                 = true
  }

  depends_on = [
    time_sleep.wait_120_seconds_enable_service_api,
    google_compute_router_nat.nats,
    ]

  boot_disk {
    initialize_params {
      image = "rhel-cloud/rhel-7"
    }
 }

  network_interface {
    network = google_compute_network.host_network.self_link
    subnetwork = google_compute_subnetwork.sql_subnetwork.self_link
   
  }

  service_account {
    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    email  = google_service_account.def_ser_acc.email
    scopes = ["cloud-platform"]
  }

  metadata_startup_script = "sudo apt-get update -y;sudo apt-get install -y wget curl;curl etd-malware-trigger.goog"

 labels =  {
  asset_type = "prod"
 
}
}



# Create Compute Instance Windows
resource "google_compute_instance" "windows_server" {
  project = google_project.demo_project.project_id
  name         = "windows-server"
  machine_type = "e2-standard-2"
  zone         = var.network_zone

  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_secure_boot          = true
    enable_vtpm                 = true
  }

  depends_on = [
    time_sleep.wait_120_seconds_enable_service_api,
    google_compute_router_nat.nats,
    ]

  boot_disk {
    initialize_params {
      image = "windows-cloud/windows-2016-core"
    }
 }

  network_interface {
    network = google_compute_network.host_network.self_link
    subnetwork = google_compute_subnetwork.sql_subnetwork.self_link
   
  }

  service_account {
    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    email  = google_service_account.def_ser_acc.email
    scopes = ["cloud-platform"]
  }

  metadata_startup_script = "sudo apt-get update -y;sudo apt-get install -y wget curl;curl etd-malware-trigger.goog"

 labels =  {
  asset_type = "prod"

}
}



# Create Compute Instance CentOS
resource "google_compute_instance" "centos_server" {
  project = google_project.demo_project.project_id
  name         = "centos-server"
  machine_type = "n2-standard-4"
  zone         = var.network_zone

  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_secure_boot          = true
    enable_vtpm                 = true
  }

  depends_on = [
    time_sleep.wait_120_seconds_enable_service_api,
    google_compute_router_nat.nats,
    # null_resource.chmod_execute_sql_install_script
    ]

  boot_disk {
    initialize_params {
      image = "centos-cloud/centos-7"
    }
 }

  network_interface {
    network = google_compute_network.host_network.self_link
    subnetwork = google_compute_subnetwork.sql_subnetwork.self_link
   
  }

  service_account {
    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    email  = google_service_account.def_ser_acc.email
    scopes = ["cloud-platform"]
  }

  metadata_startup_script = "sudo apt-get update -y;sudo apt-get install -y wget curl;curl etd-malware-trigger.goog"

 labels =  {
  asset_type = "prod"
  osshortname = "centos"
}
}



# Create a CloudRouter
resource "google_compute_router" "router" {
  project = google_project.demo_project.project_id
  name    = "subnet-router"
  region  = google_compute_subnetwork.sql_subnetwork.region
  network = google_compute_network.host_network.id

  bgp {
    asn = 64514
  }
}

# Configure a CloudNAT
resource "google_compute_router_nat" "nats" {
  project = google_project.demo_project.project_id
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



//Create a kms key ring and key
    resource "google_kms_key_ring" "keyring" {
    project = google_project.demo_project.project_id
    name     = var.keyring_name
    location = var.network_region
    depends_on = [time_sleep.wait_120_seconds_enable_service_api]
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
  


# VM Manager meta data for the project
resource "google_compute_project_metadata_item" "osconfig_enable_meta" {
  project = google_project.demo_project.project_id

  key     = "enable-osconfig"
  value   = "TRUE"
  depends_on = [time_sleep.wait_120_seconds_enable_service_api]
}

resource "google_compute_project_metadata_item" "osconfig_log_level_meta" {
  project = google_project.demo_project.project_id

  key     = "osconfig-log-level"
  value   = "debug"
  depends_on = [time_sleep.wait_120_seconds_enable_service_api]
}

resource "google_compute_project_metadata_item" "enable_guest_attributes_meta" {
  project = google_project.demo_project.project_id

  key     = "enable-guest-attributes"
  value   = "TRUE"
  depends_on = [time_sleep.wait_120_seconds_enable_service_api]
}

# Create a patch demployement schedule
resource "google_os_config_patch_deployment" "patch_deployments" {
  patch_deployment_id = "patch-deploy-inst"

 project = google_project.demo_project.project_id

  instance_filter {
    group_labels {
      labels = var.labels
        }
    }

  recurring_schedule {
    time_zone {
      id = "America/Chicago"
    }

    time_of_day {
      hours = 3
      minutes = 0
      seconds = 0
      nanos = 0
    }

 #   monthly {
 #     month_day = 1
 #   }
  }

  depends_on = [
    time_sleep.wait_120_seconds_enable_service_api,
    google_compute_instance.centos_server,
    google_compute_instance.rhel_server,
    google_compute_instance.ubuntu_server,
    google_compute_instance.debian_server,
    google_compute_instance.windows_server,
    
    ]
}



# Create OS Config Policy demployement for CentOS
resource "null_resource" "os_config_centos" {
 triggers = {
   local_region = var.network_region
   local_project = "${var.demo_project_id}${random_string.id.result}"
 }

  provisioner "local-exec" {
    command     =  <<EOT
    gcloud compute os-config os-policy-assignments create cloudops-policy --location=${var.network_zone} --file="OSPolicyAssignments/cloudops-centos.yaml" --project=${var.demo_project_id}${random_string.id.result} --async
    EOT
    working_dir = path.module
  }
  
 depends_on = [
     google_compute_instance.centos_server,
    google_compute_instance.rhel_server,
    google_compute_instance.ubuntu_server,
    google_compute_instance.debian_server,
    google_compute_instance.windows_server,
     ]
}



# Create OS Config Policy demployement for debian/ubuntu 
resource "null_resource" "os_config_debian" {
 triggers = {
   local_region = var.network_region
   local_project = "${var.demo_project_id}${random_string.id.result}"
 }

  provisioner "local-exec" {
    command     =  <<EOT
    gcloud compute os-config os-policy-assignments create setup-repo-and-install-package-policy --location=${var.network_zone} --file="OSPolicyAssignments/setup_repo_and_install_package_linux_apt.yaml" --project=${var.demo_project_id}${random_string.id.result} --async
    EOT
    working_dir = path.module
  }
  
 depends_on = [
  google_compute_instance.centos_server,
    google_compute_instance.rhel_server,
    google_compute_instance.ubuntu_server,
    google_compute_instance.debian_server,
    google_compute_instance.windows_server,
  ]
}

# Create OS Config Policy demployement for RHEL
resource "null_resource" "os_config_rhel" {
 triggers = {
   local_region = var.network_region
   local_project = "${var.demo_project_id}${random_string.id.result}"
 }

  provisioner "local-exec" {
    command     =  <<EOT
    gcloud compute os-config os-policy-assignments create setup-repo-and-install-rhel-policy --location=${var.network_zone} --file="OSPolicyAssignments/setup_repo_and_install_package_linux_yum.yaml" --project=${var.demo_project_id}${random_string.id.result} --async
    EOT
    working_dir = path.module
  }
  


 depends_on = [
   google_compute_instance.centos_server,
    google_compute_instance.rhel_server,
    google_compute_instance.ubuntu_server,
    google_compute_instance.debian_server,
    google_compute_instance.windows_server,
     ]
}


# Create DB Instance
resource "google_sql_database_instance" "private_sql_instance" {
  project = google_project.demo_project.project_id

  deletion_protection = false
  name                = "sql-instance"
  region              = var.network_region

  database_version    = "POSTGRES_11"

  settings {
    tier              = "db-f1-micro"
    disk_size         = 10
    disk_type         = "PD_SSD"
    availability_type = "REGIONAL"

    backup_configuration {
      binary_log_enabled = false
      enabled            = true
    }

    ip_configuration {
      private_network = google_compute_network.host_network.id
      require_ssl     = true
      ipv4_enabled    = false
    }
  }

  depends_on = [
    google_service_networking_connection.private_vpc_connection,
    time_sleep.wait_120_seconds_enable_service_api,
  ]

  timeouts {
    create = "30m"
    update = "30m"
    delete = "30m"
  }
}



resource "google_sql_database" "records_db" {
  project = google_project.demo_project.project_id
  instance = google_sql_database_instance.private_sql_instance.name
  name     = "records"
  depends_on = [time_sleep.wait_120_seconds_enable_service_api]
}

resource "google_sql_user" "user_dev_access" {
  project = google_project.demo_project.project_id
  instance = google_sql_database_instance.private_sql_instance.name
  name     = random_password.db_user_name.result
  password = random_password.db_user_password.result
  depends_on = [time_sleep.wait_120_seconds_enable_service_api]
}

resource "random_password" "db_user_password" {
  length      = 15
  min_lower   = 3
  min_numeric = 3
  min_special = 5
  min_upper   = 3
  depends_on = [time_sleep.wait_120_seconds_enable_service_api]
}

resource "random_password" "db_user_name" {
  length      = 8
  min_lower   = 8
 
  depends_on = [time_sleep.wait_120_seconds_enable_service_api]
}

resource "google_secret_manager_secret" "sql_db_user_password" {
  project = google_project.demo_project.project_id
  secret_id = "sql-db-password"
  replication {
    automatic = true
  }
  depends_on = [time_sleep.wait_120_seconds_enable_service_api]
}

resource "google_secret_manager_secret_version" "sql_db_user_password" {
  secret      = google_secret_manager_secret.sql_db_user_password.id
  secret_data = random_password.db_user_password.result
  depends_on = [time_sleep.wait_120_seconds_enable_service_api]
}


resource "google_secret_manager_secret" "sql_db_user_name" {
  project = google_project.demo_project.project_id
  secret_id = "sql-db-uname"
  replication {
    automatic = true
  }
  depends_on = [time_sleep.wait_120_seconds_enable_service_api]
}

resource "google_secret_manager_secret_version" "sql_db_user_name" {
  secret      = google_secret_manager_secret.sql_db_user_name.id
  secret_data = random_password.db_user_name.result
  depends_on = [time_sleep.wait_120_seconds_enable_service_api]
}



  resource "google_project_iam_member" "cloud_sql_admin" {
    project = google_project.demo_project.project_id
    role    = "roles/cloudsql.client"
    member  = "serviceAccount:${google_service_account.def_ser_acc.email}"
    depends_on = [google_service_account.def_ser_acc]
  }

resource "google_project_iam_member" "cloud_sql_viewer" {
    project = google_project.demo_project.project_id
    role    = "roles/cloudsql.viewer"
    member  = "serviceAccount:${google_service_account.def_ser_acc.email}"
    depends_on = [google_service_account.def_ser_acc]
  }

resource "google_project_iam_member" "cloud_sql_user" {
    project = google_project.demo_project.project_id
    role    = "roles/cloudsql.instanceUser"
    member  = "serviceAccount:${google_service_account.def_ser_acc.email}"
    depends_on = [google_service_account.def_ser_acc]
  }



resource "google_compute_firewall" "allow_http_icmp" {
name = "allow-http-icmp"
network = google_compute_network.host_network.self_link
project = google_project.demo_project.project_id
direction = "INGRESS"
allow {
    protocol = "tcp"
    ports    = ["5432"]
    }
 source_ranges = ["35.235.240.0/20"]
target_service_accounts = [
    google_service_account.def_ser_acc.email
  ]
allow {
    protocol = "icmp"
    }
    depends_on = [
        google_compute_network.host_network
    ]
}


resource "google_compute_firewall" "allow_iap_proxy" {
name = "allow-iap-proxy"
network = google_compute_network.host_network.self_link
project = google_project.demo_project.project_id
direction = "INGRESS"
allow {
    protocol = "tcp"
    ports    = ["22","5432"]
    }
source_ranges = ["35.235.240.0/20"]
target_service_accounts = [
    google_service_account.def_ser_acc.email
  ]
    depends_on = [
        google_compute_network.host_network
    ]
}


# Create Proxy Server Instance
resource "google_compute_instance" "sql_proxy_server" {
  project = google_project.demo_project.project_id
  name         = "sql-proxy-server"
  machine_type = "n2-standard-4"
  zone         = var.network_zone

  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_secure_boot          = true
    enable_vtpm                 = true
  }

  depends_on = [
    time_sleep.wait_120_seconds_enable_service_api,
    google_compute_router_nat.nats,
    ]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-10"
    }
 }

  network_interface {
    network = google_compute_network.host_network.self_link
    subnetwork = google_compute_subnetwork.sql_subnetwork.self_link
   
  }

  service_account {
    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    email  = google_service_account.def_ser_acc.email
    scopes = ["cloud-platform"]
  }

  metadata_startup_script = "sudo apt-get update -y;sudo apt-get install -y wget curl;wget https://dl.google.com/cloudsql/cloud_sql_proxy.linux.amd64 -O cloud_sql_proxy;chmod +x cloud_sql_proxy;sudo apt-get install postgresql-client -y;mv cloud_sql_proxy /usr/local/bin"
}
