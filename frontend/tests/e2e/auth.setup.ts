import { expect, test as setup } from "@playwright/test";

import { createAccount, newPassword } from "./support/accounts";
import { changePassword, LIVE, LIVE_ONLY, OPERATOR_STATE, signIn } from "./support/session";

// A fresh operator account for the workflow (Phase 9 M8). The administrator
// creates it with a temporary password; the operator signs in through the UI,
// is held on the password change, sets their own password and reaches the
// console. The browser state saved here is the opaque session cookie only.

setup("an operator signs in and sets their own password", async ({ page }) => {
  setup.skip(!LIVE, LIVE_ONLY);
  const operator = await createAccount("operator");
  await signIn(page, operator);
  await changePassword(page, operator.password, newPassword());
  await expect(page.getByTestId("current-username")).toHaveText(operator.username);
  await page.context().storageState({ path: OPERATOR_STATE });
});
