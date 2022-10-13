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


# The below three variable must be updated for the PoC
organization_id = "XXXXXXXXXXX"
billing_account = "XXXXXX-XXXXXXX-XXXXXX"
proxy_access_identities = "user:username@domain.com"



# Below variable can be update per customer use cases
folder_name = "Security Foundation Sol "
demo_project_id = "sf-sol-poc-" 
vpc_network_name = "host-network"
network_region = "us-east1"
network_zone = "us-east1-b"

keyring_name = "my-keyring"
crypto_key_name = "my-symmetric-key"

labels = {
  asset_type = "prod"
}


