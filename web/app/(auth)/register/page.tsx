import { RegisterForm } from "@/components/auth/RegisterForm";
import { isLoopback, publicBaseUrl } from "@/lib/nightwatch/public-url";

export const metadata = { title: "Set up your organization" };

export default async function RegisterPage() {
  const baseUrl = await publicBaseUrl();
  return <RegisterForm baseUrl={baseUrl} loopback={isLoopback(baseUrl)} />;
}
