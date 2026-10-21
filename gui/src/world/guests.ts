// Stable identities use the hub's persistent account id; names are display labels.
import type { AccountName, HubId } from "./accounts";

export interface GuestPrincipal {
  hub: HubId;
  id: string;
  account: AccountName;
}
