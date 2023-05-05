import { ModuleOptions } from "simple-oauth2";

export const OptionsDefault = {
  scopeSeparator: "",
  credentialsEncodingMode: "strict",
  bodyFormat: "form",
  authorizationMethod: "header",
} as ModuleOptions["options"];

export const ClientDefault: ModuleOptions["client"] = {
  id: "",
  secret: "",
  secretParamName: "client_secret",
  idParamName: "client_id",
};

export const AuthDefault: ModuleOptions["auth"] = {
  authorizeHost: "",
  authorizePath: "/oauth/authorize",
  tokenHost: "",
  tokenPath: "/oauth/token",
  refreshPath: "/oauth/token",
  revokePath: "/oauth/revoke",
};
