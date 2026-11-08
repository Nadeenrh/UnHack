import { Shell } from "@/components/shell/Shell";
import { requirePageProvider } from "@/lib/nightwatch/page-auth";

export default async function ProviderLayout({ children }: { children: React.ReactNode }) {
  const session = await requirePageProvider();
  return (
    <Shell
      nav={[
        { href: "/provider", label: "Clients", exact: true },
        { href: "/provider/connect", label: "Connect a client" },
      ]}
      user={{ name: `${session.firstName} ${session.lastName}`, email: session.email }}
    >
      {children}
    </Shell>
  );
}
