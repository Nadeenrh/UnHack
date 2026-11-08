import Image from "next/image";

// The Nightwatch shield, cut from the brand logo with a transparent background.
// Every screen uses this one component, next to the "Nightwatch" wordmark.
// `dark` is kept so existing callers still compile; the shield reads on light and dark backgrounds.
export function Logo({ size = 28 }: { dark?: boolean; size?: number }) {
  return <Image src="/brand/nightwatch-shield.png" alt="" aria-hidden="true" width={size} height={size} priority className="shrink-0" />;
}
