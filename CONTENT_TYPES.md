# MCP Protocol Content Types - Official Documentation

This document provides the definitive reference for supported content types in the Model Context Protocol (MCP), based on the official specification.

## Official Documentation Sources

### Primary References
1. **Official Schema Definition**: https://github.com/modelcontextprotocol/specification/blob/main/schema/2025-06-18/schema.ts
2. **Tools Documentation**: https://modelcontextprotocol.io/docs/concepts/tools
3. **Protocol Specification**: https://spec.modelcontextprotocol.io/specification/

### Content Type Union
According to the official schema, `ContentBlock` (used in tool responses) supports:
```typescript
export type ContentBlock =
  | TextContent
  | ImageContent
  | AudioContent
  | ResourceLink
  | EmbeddedResource;
```

## Supported Content Types

### 1. TextContent
For plain text responses and markdown content.

```typescript
{
  type: "text";
  text: string;
  annotations?: Annotations;
  _meta?: { [key: string]: unknown };
}
```

**Use Cases:**
- Tool execution results
- Error messages
- Markdown documentation
- JSON/XML data as text

### 2. ImageContent
For images (charts, diagrams, screenshots).

```typescript
{
  type: "image";
  data: string; // Base64-encoded image data
  mimeType: string; // e.g., "image/png", "image/jpeg"
  annotations?: Annotations;
  _meta?: { [key: string]: unknown };
}
```

**Use Cases:**
- Charts and graphs
- Network diagrams
- Screenshots
- Visual data representations

### 3. AudioContent
For audio data (voice recordings, sound files).

```typescript
{
  type: "audio";
  data: string; // Base64-encoded audio data
  mimeType: string; // e.g., "audio/wav", "audio/mp3"
  annotations?: Annotations;
  _meta?: { [key: string]: unknown };
}
```

**Use Cases:**
- Voice recordings
- Audio alerts
- Sound notifications

### 4. ResourceLink
For referencing external resources without embedding content.

```typescript
{
  type: "resource_link";
  uri: string; // Resource URI
  name: string; // Resource identifier
  title?: string; // Display name
  description?: string; // Resource description
  mimeType?: string; // Content type
  annotations?: Annotations;
  size?: number; // Size in bytes
  _meta?: { [key: string]: unknown };
}
```

**Use Cases:**
- References to external files
- Links to web resources
- Pointers to large datasets
- File references without embedding

### 5. EmbeddedResource
For embedding actual resource content in responses.

```typescript
{
  type: "resource";
  resource: TextResourceContents | BlobResourceContents;
  annotations?: Annotations;
  _meta?: { [key: string]: unknown };
}
```

#### TextResourceContents
```typescript
{
  uri: string; // Resource identifier
  mimeType?: string; // e.g., "text/plain", "application/json"
  text: string; // Actual text content
  _meta?: { [key: string]: unknown };
}
```

#### BlobResourceContents
```typescript
{
  uri: string; // Resource identifier
  mimeType?: string; // e.g., "application/pdf", "application/zip"
  blob: string; // Base64-encoded binary data
  _meta?: { [key: string]: unknown };
}
```

**Use Cases:**
- Generated files (certificates, configs)
- Binary downloads
- Document attachments
- Data exports

## Supporting Types

### Annotations
Optional metadata for content items:

```typescript
{
  audience?: ("user" | "assistant")[]; // Target audience
  priority?: number; // 0-1, where 1 is most important
  lastModified?: string; // ISO 8601 timestamp
}
```

### Meta Fields
All content types support optional `_meta` field for custom metadata:

```typescript
_meta?: { [key: string]: unknown };
```

## Common Patterns

### Multi-Content Responses
Tools can return multiple content items:

```typescript
{
  content: [
    {
      type: "text",
      text: "## Certificate Generated\n\nYour SSL certificate has been created successfully."
    },
    {
      type: "resource",
      resource: {
        uri: "data:application/x-pem-file;base64,LS0tLS1CRUdJTi...",
        mimeType: "application/x-pem-file",
        text: "-----BEGIN CERTIFICATE-----\n..."
      }
    }
  ]
}
```

### Data URIs for Downloads
Use data URIs for downloadable content:

```typescript
{
  type: "resource",
  resource: {
    uri: "data:application/json;base64,eyJuYW1lIjoidGVzdCJ9",
    mimeType: "application/json",
    text: '{"name":"test"}'
  }
}
```

## Migration Notes

### Removed Content Types
The following content types are **NOT** supported in the official MCP protocol:

- ❌ `blob` type (use `EmbeddedResource` with `BlobResourceContents`)
- ❌ `file` type (use `ResourceLink` or `EmbeddedResource`)
- ❌ `binary` type (use `EmbeddedResource` with `BlobResourceContents`)

### Best Practices

1. **Use appropriate types**: Choose the most specific content type for your data
2. **Include MIME types**: Always specify MIME types for binary content
3. **Add annotations**: Use annotations to provide context about content priority and audience
4. **Data URIs for files**: Use data URIs for downloadable file content
5. **Error handling**: Set `isError: true` in `ToolResponse` for error conditions

## Implementation in This Project

This project's content types are defined in `/src/tools/types.ts` and conform to the official MCP specification. The certificate generation tool demonstrates proper usage of multiple content types in a single response.

## Version Information

- **MCP Protocol Version**: 2025-06-18
- **Schema Source**: https://github.com/modelcontextprotocol/specification/blob/main/schema/2025-06-18/schema.ts
- **Last Updated**: January 2025
