"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const LINKS = [
  { href: "/", label: "Overview" },
  { href: "/projects", label: "Projects" },
  { href: "/findings", label: "Findings" },
  { href: "/reports", label: "Scan reports" },
  { href: "/retests", label: "Retests" },
  { href: "/retest-reports", label: "Retest reports" },
  { href: "/rules", label: "Rule catalog" },
];

export function Nav() {
  const pathname = usePathname();
  return (
    <nav aria-label="Main" className="nav">
      <ul>
        {LINKS.map((link) => {
          const active = link.href === "/" ? pathname === "/" : pathname.startsWith(link.href);
          return (
            <li key={link.href}>
              <Link href={link.href} aria-current={active ? "page" : undefined}>
                {link.label}
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
