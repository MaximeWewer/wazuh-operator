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

// DefaultWazuhPipelineVersion is the version of the embedded default pipeline
const DefaultWazuhPipelineVersion = "4.x"

// DefaultWazuhPipelineJSON contains the default Wazuh ingest pipeline
// Based on https://github.com/wazuh/wazuh/blob/master/extensions/filebeat/7.x/wazuh-module/alerts/ingest/pipeline.json
// This pipeline handles:
// - JSON parsing
// - GeoIP enrichment for various IP fields
// - Timestamp processing
// - Field cleanup
// Users can override with a custom pipeline via ConfigMap reference
const DefaultWazuhPipelineJSON = `{
  "description": "Wazuh alerts pipeline",
  "processors": [
    {
      "json": {
        "field": "message",
        "add_to_root": true
      }
    },
    {
      "geoip": {
        "field": "data.srcip",
        "target_field": "GeoLocation",
        "properties": ["city_name", "country_name", "region_name", "location"],
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "data.aws.sourceIPAddress",
        "target_field": "GeoLocation",
        "properties": ["city_name", "country_name", "region_name", "location"],
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "data.aws.client_ip",
        "target_field": "GeoLocation",
        "properties": ["city_name", "country_name", "region_name", "location"],
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "data.aws.service.action.networkConnectionAction.remoteIpDetails.ipAddressV4",
        "target_field": "GeoLocation",
        "properties": ["city_name", "country_name", "region_name", "location"],
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "data.aws.httpRequest.clientIp",
        "target_field": "GeoLocation",
        "properties": ["city_name", "country_name", "region_name", "location"],
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "data.gcp.jsonPayload.sourceIP",
        "target_field": "GeoLocation",
        "properties": ["city_name", "country_name", "region_name", "location"],
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "data.office365.ClientIP",
        "target_field": "GeoLocation",
        "properties": ["city_name", "country_name", "region_name", "location"],
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "data.win.eventdata.ipAddress",
        "target_field": "GeoLocation",
        "properties": ["city_name", "country_name", "region_name", "location"],
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "data.github.actor_ip",
        "target_field": "GeoLocation",
        "properties": ["city_name", "country_name", "region_name", "location"],
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "date": {
        "field": "timestamp",
        "target_field": "@timestamp",
        "formats": ["ISO8601"],
        "ignore_failure": false
      }
    },
    {
      "date_index_name": {
        "field": "timestamp",
        "index_name_prefix": "{{fields.index_prefix}}-",
        "date_rounding": "d",
        "date_formats": ["ISO8601"],
        "ignore_failure": false
      }
    },
    {
      "remove": {
        "field": ["message", "ecs", "beat", "input_type", "tags", "count", "@version", "log", "offset", "type", "host", "fields", "event", "fileset", "service", "agent.hostname", "agent.id", "agent.ephemeral_id", "agent.type", "agent.version"],
        "ignore_missing": true,
        "ignore_failure": true
      }
    }
  ],
  "on_failure": [
    {
      "drop": {}
    }
  ]
}`
