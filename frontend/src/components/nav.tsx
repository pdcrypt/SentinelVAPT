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
  { href: "/account", label: "Account" },
];

/** Shown to global administrators. Navigation only: the API refuses these
 *  pages' data to anyone else, whatever the menu shows. */
const ADMIN_LINKS = [
  { href: "/admin/users", label: "Accounts" },
  { href: "/admin/audit", label: "Platform audit log" },
];

export function Nav({ admin = false }: { admin?: boolean }) {
  const pathname = usePathname();
  const links = admin ? [...LINKS, ...ADMIN_LINKS] : LINKS;
  return (
    <nav aria-label="Main" className="nav">
      <ul>
        {links.map((link) => {
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
