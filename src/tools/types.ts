import { z } from "zod";

export interface ToolResponse {
    content: Array<{
        type: "text";
        text: string;
    }>;
    isError?: boolean;
}

export interface ToolDefinition {
    name: string;
    description: string;
    schema: object;
    handler: (params: any) => Promise<ToolResponse>;
}
