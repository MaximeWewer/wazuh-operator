# OpenSearch Index Management Examples

Manage OpenSearch indices, templates and lifecycle (ISM). For security CRDs,
see [../opensearch-security/](../opensearch-security/).

| File | Kind | Description |
| ---- | ---- | ----------- |
| [opensearchindex-basic.yaml](opensearchindex-basic.yaml) | OpenSearchIndex | Managed index |
| [opensearchindextemplate-basic.yaml](opensearchindextemplate-basic.yaml) | OpenSearchIndexTemplate | Index template |
| [opensearchcomponenttemplate-basic.yaml](opensearchcomponenttemplate-basic.yaml) | OpenSearchComponentTemplate | Reusable template component |
| [opensearchismpolicy-basic.yaml](opensearchismpolicy-basic.yaml) | OpenSearchISMPolicy | Index State Management policy |

## Usage

```bash
# ISM policy + an index template that references it
kubectl apply -f opensearchismpolicy-basic.yaml
kubectl apply -f opensearchindextemplate-basic.yaml
```

## Related Documentation

- [OpenSearch Indices](../../features/opensearch-indices.md)
