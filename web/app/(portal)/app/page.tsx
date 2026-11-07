import Link from "next/link";
import { redirect } from "next/navigation";
import { isProvider } from "@/lib/nightwatch/access";
import { requirePageSession } from "@/lib/nightwatch/page-auth";

export default async function AppIndex() {
  const session = await requirePageSession("/app");
  if (session.memberships.length) redirect(`/app/${session.memberships[0].orgId}`);
  if (isProvider(session)) redirect("/provider");

  return (
    <main className="flex min-h-screen items-center justify-center p-6">
      <div className="max-w-md rounded-lg border border-line bg-panel p-8 text-center">
        <h1 className="text-xl font-semibold">You&apos;re not part of an organization yet</h1>
        <p className="mt-2 text-muted">Ask an owner to add you, or set up your own organization.</p>
        <Link href="/register" className="mt-6 inline-block rounded-md bg-ink px-4 py-2 font-semibold text-night">
          Set up an organization
        </Link>
      </div>
    </main>
  );
}
