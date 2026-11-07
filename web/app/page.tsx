import Link from "next/link";
import { redirect } from "next/navigation";
import { Logo } from "@/components/shell/Logo";
import { isProvider } from "@/lib/nightwatch/access";
import { getServerSession } from "@/lib/nightwatch/auth";

// Signed in → straight to the right portal. Signed out → a plain front door.
export default async function Home() {
  const session = await getServerSession();
  if (session) {
    if (session.memberships.length) redirect(`/app/${session.memberships[0].orgId}`);
    if (isProvider(session)) redirect("/provider");
    redirect("/app");
  }

  return (
    <main className="flex min-h-screen flex-col bg-sidebar text-ink">
      <div className="mx-auto flex w-full max-w-3xl flex-1 flex-col justify-center px-6 py-16">
        <div className="flex items-center gap-3">
          <Logo size={44} />
          <span className="text-3xl font-semibold tracking-tight">Nightwatch</span>
        </div>
        <h1 className="mt-10 max-w-2xl text-4xl leading-tight font-semibold tracking-tight sm:text-5xl">
          Someone is always watching your network, even at 2 a.m.
        </h1>
        <p className="mt-5 max-w-xl text-lg text-white/75">
          For towns, utilities and small organizations without a security team. Nightwatch investigates every alert, explains it in plain
          language, and asks before it changes anything.
        </p>
        <div className="mt-10 flex flex-wrap gap-3">
          <Link href="/login" className="rounded-md bg-lantern px-5 py-2.5 font-semibold text-night hover:brightness-105">
            Sign in
          </Link>
          <Link href="/register" className="rounded-md px-5 py-2.5 font-semibold text-white ring-1 ring-white/30 hover:bg-white/5">
            Set up your organization
          </Link>
        </div>
      </div>
    </main>
  );
}
