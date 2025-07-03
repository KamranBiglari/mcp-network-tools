import { z } from "zod";

// Official MCP Content Types based on the authoritative schema
// Reference: https://github.com/modelcontextprotocol/specification/blob/main/schema/2025-06-18/schema.ts

export interface Annotations {
    audience?: ("user" | "assistant")[];
    priority?: number; // 0-1, where 1 is most important
    lastModified?: string; // ISO 8601 formatted string
}

export interface TextContent {
    type: "text";
    text: string;
    annotations?: Annotations;
    _meta?: { [key: string]: unknown };
}

export interface ImageContent {
    type: "image";
    data: string; // Base64-encoded image data
    mimeType: string;
    annotations?: Annotations;
    _meta?: { [key: string]: unknown };
}

export interface AudioContent {
    type: "audio";
    data: string; // Base64-encoded audio data
    mimeType: string;
    annotations?: Annotations;
    _meta?: { [key: string]: unknown };
}

export interface ResourceLink {
    type: "resource_link";
    uri: string;
    name: string;
    title?: string;
    description?: string;
    mimeType?: string;
    annotations?: Annotations;
    size?: number;
    _meta?: { [key: string]: unknown };
}

// Resource contents for embedded resources
export interface TextResourceContents {
    uri: string;
    mimeType?: string;
    text: string;
    _meta?: { [key: string]: unknown };
}

export interface BlobResourceContents {
    uri: string;
    mimeType?: string;
    blob: string; // Base64-encoded binary data
    _meta?: { [key: string]: unknown };
}

export interface EmbeddedResource {
    type: "resource";
    resource: TextResourceContents | BlobResourceContents;
    annotations?: Annotations;
    _meta?: { [key: string]: unknown };
}

export type ContentItem = 
    | TextContent 
    | ImageContent 
    | AudioContent 
    | ResourceLink 
    | EmbeddedResource;

export interface ToolResponse {
    content: Array<ContentItem>;
    isError?: boolean;
    _meta?: { [key: string]: unknown };
}

export interface ToolDefinition {
    name: string;
    description: string;
    schema: object;
    handler: (params: any) => Promise<ToolResponse>;
}
