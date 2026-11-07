import Link from "next/link";

export default function NotFound() {
  return (
    <main className="flex min-h-screen items-center justify-center p-6">
      <div className="max-w-md rounded-lg border border-line bg-panel p-8 text-center">
        <h1 className="text-xl font-semibold">Page not found</h1>
        <p className="mt-2 text-muted">It doesn&apos;t exist, or your account doesn&apos;t have access to it.</p>
        <Link href="/" className="mt-6 inline-block rounded-md bg-ink px-4 py-2 font-semibold text-night">
          Go to your dashboard
        </Link>
      </div>
    </main>
  );
}
