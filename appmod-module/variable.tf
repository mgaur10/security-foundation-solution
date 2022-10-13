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




variable appmodtag {  
}

variable organization_id {
}


variable vpc_network_name {
}

variable network_zone{
}

variable network_region {
}

variable random_string {

}

variable folder_id {
}

variable billing_account {    
}

variable demo_project_id {
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


variable proxy_access_identities {  
}



#GKE - demo

variable "name" {
type        = string
description = "Name given to the new GKE cluster"
default     = "online-boutique2"
}

variable "namespace" {
type        = string
description = "Kubernetes Namespace in which the Online Boutique resources are to be deployed"
default     = "default"
}

variable "filepath_manifest" {
type        = string
description = "Path to the Kubernetes manifest that defines the Online Boutique resources"
default     = "appmod-module/release/kubernetes-manifests.yaml"
}

variable "memorystore" {
type        = bool
description = "If true, Online Boutique's in-cluster Redis cache will be replaced with a Google Cloud Memorystore Redis cache"
default = false
}


variable "global_policy_evaluation_mode" {
description = "(optional) - Controls the evaluation of a Google-maintained global admission policy\nfor common system-level images. Images not covered by the global\npolicy will be subject to the project admission policy. Possible values: [\"ENABLE\", \"DISABLE\"]"
type        = string
default     = "ENABLE"
}



variable "evaluation_mode" {
description = "(optional) - "
type        = string
default     = "ALWAYS_DENY"
#"ALWAYS_ALLOW", "REQUIRE_ATTESTATION"
}

variable "enforcement_mode" {
description = "(optional) - "
type        = string
default     = "DRYRUN_AUDIT_LOG_ONLY"
# "ENFORCED_BLOCK_AND_AUDIT_LOG"
}

variable keyring_name {
}

variable crypto_key_name {
}