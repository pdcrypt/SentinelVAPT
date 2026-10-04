import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

// Security rules (ADR 0013). Every value from the API is untrusted, so no code
// path may turn a string into markup, and the browser must never learn the
// API address. tests/unit/eslint-rules.test.ts proves these rules fire.
export const securityRules = {
  "react/no-danger": "error",
  "no-restricted-syntax": [
    "error",
    {
      selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
      message: "Raw HTML rendering is forbidden: render untrusted values with <SafeText>.",
    },
    {
      selector: "JSXAttribute[name.name=/^srcdoc$/i]",
      message: "iframe srcDoc renders raw HTML; previews use the sandboxed /artifacts route.",
    },
    {
      selector:
        "AssignmentExpression > MemberExpression.left[property.name=/^(innerHTML|outerHTML)$/]",
      message: "Assigning HTML strings is forbidden.",
    },
    {
      selector: "CallExpression[callee.property.name='insertAdjacentHTML']",
      message: "insertAdjacentHTML renders raw HTML and is forbidden.",
    },
    {
      selector:
        "CallExpression[callee.object.name='document'][callee.property.name=/^write(ln)?$/]",
      message: "document.write is forbidden.",
    },
    {
      selector: "MemberExpression[object.property.name='env'][property.name=/^NEXT_PUBLIC_/]",
      message:
        "NEXT_PUBLIC_ variables are bundled into browser code; the API address must stay server-only.",
    },
    {
      selector:
        "JSXOpeningElement[name.name='iframe']:not(:has(JSXAttribute[name.name='sandbox']))",
      message: 'Every iframe must be sandboxed (report previews use sandbox="").',
    },
  ],
};

const config = [
  ...nextVitals,
  ...nextTs,
  {
    files: ["src/**/*.{ts,tsx}"],
    rules: {
      ...securityRules,
      "@typescript-eslint/no-unused-vars": ["warn", { argsIgnorePattern: "^_" }],
    },
  },
  {
    ignores: [
      ".next/**",
      "node_modules/**",
      "playwright-report/**",
      "test-results/**",
      "next-env.d.ts",
      "src/lib/api/schema.d.ts",
    ],
  },
];

export default config;
