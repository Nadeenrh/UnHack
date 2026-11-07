"use client";

import { CodeBlock, IntegrationSnippet } from "./IntegrationSnippet";

const WAZUH_AGENT_DOCS = "https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html";

function installCommands(baseUrl: string): string {
  return [
    `sudo curl -fsSL ${baseUrl}/downloads/custom-nightwatch.py -o /var/ossec/integrations/custom-nightwatch.py`,
    "sudo cp /var/ossec/integrations/slack /var/ossec/integrations/custom-nightwatch",
    "sudo chown root:wazuh /var/ossec/integrations/custom-nightwatch*",
    "sudo chmod 750 /var/ossec/integrations/custom-nightwatch*",
  ].join("\n");
}

function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <li className="grid grid-cols-[2rem_minmax(0,1fr)] gap-3">
      <span aria-hidden className="flex size-7 items-center justify-center rounded-full bg-lantern text-sm font-semibold text-night">
        {n}
      </span>
      <div className="min-w-0">
        <h3 className="font-semibold">{title}</h3>
        <div className="mt-1 text-sm text-muted">{children}</div>
      </div>
    </li>
  );
}

/**
 * How to point a Wazuh server at Nightwatch. Shown right after sign-up (with the real key,
 * which exists only at that moment) and on the Connect page (with a placeholder).
 */
export function ConnectSteps({
  baseUrl,
  ingestKey,
  keyPrefix,
  loopback,
}: {
  baseUrl: string;
  ingestKey: string | null;
  keyPrefix?: string | null;
  loopback: boolean;
}) {
  const hookUrl = `${baseUrl}/api/v1/ingest/wazuh`;
  return (
    <div className="space-y-4">
      {loopback && (
        <p role="note" className="rounded-md bg-lantern-soft px-3 py-2 text-sm">
          You&apos;re opening Nightwatch as <span className="font-mono">{new URL(baseUrl).host}</span>, which only works on this computer.
          Your Wazuh server needs this computer&apos;s network address instead (for example{" "}
          <span className="font-mono">http://192.168.8.50:3000</span>). Set <span className="font-mono">NIGHTWATCH_PUBLIC_URL</span>{" "}
          to fill it in here.
        </p>
      )}
      <ol className="space-y-6">
        <Step n={1} title="Install the Wazuh agent on each computer">
          Front desk PCs, laptops and the file server. Point each agent at your Wazuh server. The name you give an agent is the
          name you&apos;ll see in Nightwatch, so use something you&apos;ll recognise, like <span className="font-mono">FRONTDESK-PC</span>.{" "}
          <a href={WAZUH_AGENT_DOCS} target="_blank" rel="noreferrer" className="font-medium text-info hover:underline">
            Wazuh&apos;s install guide
          </a>
        </Step>
        <Step n={2} title="Add the Nightwatch forwarder to your Wazuh server">
          Run these on the Wazuh server. They download a small script that passes each alert to Nightwatch.
          <CodeBlock code={installCommands(baseUrl)} label="install commands" />
        </Step>
        <Step n={3} title="Tell Wazuh where to send alerts">
          Paste this inside <span className="font-mono">&lt;ossec_config&gt;</span> in{" "}
          <span className="font-mono">/var/ossec/etc/ossec.conf</span>, then restart with{" "}
          <span className="font-mono">sudo systemctl restart wazuh-manager</span>.
          {ingestKey ? (
            <span className="mt-1 block font-medium text-ink">Your key is already filled in.</span>
          ) : (
            <span className="mt-1 block">
              Replace the key with yours
              {keyPrefix ? (
                <>
                  {" "}
                  (it starts with <span className="font-mono">{keyPrefix}</span>)
                </>
              ) : null}
              . Lost it? An owner can issue a new one in Settings.
            </span>
          )}
          <IntegrationSnippet hookUrl={hookUrl} ingestKey={ingestKey} />
        </Step>
        <Step n={4} title="Check it worked">
          Each computer appears on the Machines page as soon as it sends its first alert. Serious alerts open an incident, which
          Nightwatch investigates and explains here.
        </Step>
      </ol>
    </div>
  );
}
