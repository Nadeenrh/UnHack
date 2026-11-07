"use client";

import { useState } from "react";

export const KEY_PLACEHOLDER = "nwk_PASTE_YOUR_INGEST_KEY";

export function integrationXml(hookUrl: string, ingestKey: string | null): string {
  return [
    "<integration>",
    "  <name>custom-nightwatch</name>",
    `  <hook_url>${hookUrl}</hook_url>`,
    `  <api_key>${ingestKey ?? KEY_PLACEHOLDER}</api_key>`,
    "  <level>3</level>",
    "  <alert_format>json</alert_format>",
    "</integration>",
  ].join("\n");
}

/** A code block with a copy button. */
export function CodeBlock({ code, label }: { code: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="mt-2 overflow-hidden rounded-md bg-night text-white/90">
      <div className="flex justify-end border-b border-white/10 px-2 py-1">
        <button
          type="button"
          onClick={async () => {
            await navigator.clipboard.writeText(code).catch(() => undefined);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
          }}
          className="rounded px-2 py-0.5 text-xs font-medium text-white/80 hover:bg-white/10"
          aria-label={`Copy ${label}`}
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="p-3 font-mono text-xs leading-relaxed break-all whitespace-pre-wrap">
        <code>{code}</code>
      </pre>
    </div>
  );
}

export function IntegrationSnippet({ hookUrl, ingestKey }: { hookUrl: string; ingestKey: string | null }) {
  return <CodeBlock code={integrationXml(hookUrl, ingestKey)} label="Wazuh integration settings" />;
}
