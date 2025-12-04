/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package config

// DefaultWazuhTemplateVersion is the version of the embedded default template
const DefaultWazuhTemplateVersion = "4.x"

// DefaultWazuhTemplateJSON contains the default Wazuh index template
// Based on https://github.com/wazuh/wazuh/blob/master/extensions/elasticsearch/7.x/wazuh-template.json
// This is a simplified version that captures essential mappings
// Users can override with a custom template via ConfigMap reference
const DefaultWazuhTemplateJSON = `{
  "order": 1,
  "index_patterns": [
    "wazuh-alerts-4.x-*",
    "wazuh-archives-4.x-*"
  ],
  "settings": {
    "index.refresh_interval": "5s",
    "index.number_of_shards": "3",
    "index.number_of_replicas": "0",
    "index.mapping.total_fields.limit": 10000,
    "index.auto_expand_replicas": "0-1",
    "index.query.default_field": [
      "agent.id",
      "agent.name",
      "agent.ip",
      "rule.id",
      "rule.level",
      "rule.description",
      "rule.groups",
      "data.srcip",
      "data.dstip",
      "data.srcuser",
      "data.dstuser",
      "full_log",
      "location",
      "manager.name"
    ]
  },
  "mappings": {
    "dynamic_templates": [
      {
        "string_as_keyword": {
          "match_mapping_type": "string",
          "mapping": {
            "type": "keyword"
          }
        }
      }
    ],
    "properties": {
      "@timestamp": {
        "type": "date"
      },
      "timestamp": {
        "type": "date",
        "format": "date_optional_time||epoch_millis"
      },
      "agent": {
        "properties": {
          "id": { "type": "keyword" },
          "name": { "type": "keyword" },
          "ip": { "type": "ip" }
        }
      },
      "manager": {
        "properties": {
          "name": { "type": "keyword" }
        }
      },
      "rule": {
        "properties": {
          "id": { "type": "keyword" },
          "level": { "type": "integer" },
          "description": { "type": "text" },
          "groups": { "type": "keyword" },
          "mitre": {
            "properties": {
              "id": { "type": "keyword" },
              "tactic": { "type": "keyword" },
              "technique": { "type": "keyword" }
            }
          },
          "cis": { "type": "keyword" },
          "pci_dss": { "type": "keyword" },
          "hipaa": { "type": "keyword" },
          "nist_800_53": { "type": "keyword" },
          "gpg13": { "type": "keyword" },
          "gdpr": { "type": "keyword" },
          "tsc": { "type": "keyword" }
        }
      },
      "data": {
        "properties": {
          "srcip": { "type": "ip" },
          "dstip": { "type": "ip" },
          "srcport": { "type": "integer" },
          "dstport": { "type": "integer" },
          "srcuser": { "type": "keyword" },
          "dstuser": { "type": "keyword" },
          "protocol": { "type": "keyword" },
          "action": { "type": "keyword" },
          "status": { "type": "keyword" }
        }
      },
      "location": {
        "type": "keyword"
      },
      "full_log": {
        "type": "text"
      },
      "decoder": {
        "properties": {
          "name": { "type": "keyword" },
          "parent": { "type": "keyword" }
        }
      },
      "syscheck": {
        "properties": {
          "path": { "type": "keyword" },
          "sha1_after": { "type": "keyword" },
          "sha256_after": { "type": "keyword" },
          "md5_after": { "type": "keyword" },
          "size_after": { "type": "long" },
          "perm_after": { "type": "keyword" },
          "uid_after": { "type": "keyword" },
          "gid_after": { "type": "keyword" },
          "uname_after": { "type": "keyword" },
          "gname_after": { "type": "keyword" },
          "mtime_after": { "type": "date" },
          "event": { "type": "keyword" }
        }
      },
      "GeoLocation": {
        "properties": {
          "location": { "type": "geo_point" },
          "city_name": { "type": "keyword" },
          "country_name": { "type": "keyword" },
          "region_name": { "type": "keyword" }
        }
      },
      "vulnerability": {
        "properties": {
          "cve": { "type": "keyword" },
          "title": { "type": "text" },
          "severity": { "type": "keyword" },
          "cvss": {
            "properties": {
              "cvss3": {
                "properties": {
                  "base_score": { "type": "float" }
                }
              }
            }
          },
          "package": {
            "properties": {
              "name": { "type": "keyword" },
              "version": { "type": "keyword" }
            }
          }
        }
      }
    }
  }
}`
