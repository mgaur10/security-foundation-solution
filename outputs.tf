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


output "_01_core_project_infra_mod_id" {
  value = google_project.demo_project.project_id
}

/* Uncomment to implement IDS module
output "_02_ids_project_id" {
  value = module.ids_deploy.ids_project_id
}
 */

output "_03_appmod_project_id" {
  value = module.appmod_deploy.appmod_project_id
}
output "_04_dlp_vpcsc_project_id" {
  value = module.dlp_deploy.dlp_project_id
}


/* Uncomment to implement IDS module
output "_05_ids_victim_server_ip" {
  value = "IDS victim server ip - 192.168.10.20"
 
}

output "_06_ids_attacker_server" {
  value = "IDS attacker server ip - 192.168.10.10"
 
}


output "_07_ids_iap_ssh_attacker_server" {
  value = "gcloud compute ssh --zone ${var.network_zone} ${module.ids_deploy.ids_attacker_machine}  --tunnel-through-iap --project ${module.ids_deploy.ids_project_id}"
 }

output "_08_ids_sample_attack_command" {
  value = "curl http://192.168.10.20/cgi-bin/../../../..//bin/cat%20/etc/passwd"
 }

*/

output "_09_start_sql_proxy_ssh_tunnel" {
  value = "gcloud compute ssh ${google_compute_instance.sql_proxy_server.name} --project ${var.demo_project_id}${random_string.id.result} --zone ${var.network_zone} --tunnel-through-iap"
}

output "_10_sql_instance_connection_name" {
  value = google_sql_database_instance.private_sql_instance.connection_name
}

output "_11_initiate_sql_listner_connection" {
  value = "cloud_sql_proxy -instances=${var.demo_project_id}${random_string.id.result}:${var.network_region}:sql-instance=tcp:0.0.0.0:5432"
}
   
  output "_12_retrieve_db_username" {
  value = "gcloud secrets versions access ${google_secret_manager_secret_version.sql_db_user_name.id} --secret ${google_secret_manager_secret.sql_db_user_name.id}"
}
   
 output "_13_retrieve_db_password" {
  value = "gcloud secrets versions access ${google_secret_manager_secret_version.sql_db_user_password.id} --secret ${google_secret_manager_secret.sql_db_user_password.id}"
}
   
output "_14_sql_client_command" {
  value = "psql \"host=127.0.0.1 port=5432 sslmode=disable dbname=${google_sql_database.records_db.name} user=USERNAME\""
 
} 
