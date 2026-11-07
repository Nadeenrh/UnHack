// A lantern: the night watch's light. Lantern amber is the colour that means "needs you".
export function Logo({ dark = false, size = 28 }: { dark?: boolean; size?: number }) {
  const frame = dark ? "#13203a" : "#ffffff";
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <path d="M12 4h8M16 4v3" stroke={frame} strokeWidth="2" strokeLinecap="round" />
      <rect x="9" y="7" width="14" height="19" rx="3" fill="none" stroke={frame} strokeWidth="2" />
      <path d="M16 11c2.4 2.6 3 4.6 3 6.2A3 3 0 0 1 13 17.2c0-1.6.6-3.6 3-6.2Z" fill="#d99a0b" />
      <path d="M10 26h12" stroke={frame} strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}
