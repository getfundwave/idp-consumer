import { Session, SessionData, SessionOptions } from "express-session";
import { ModuleOptions } from "simple-oauth2";

export type StaticRedirectOrigin = string | RegExp | Array<string | RegExp>;
export type CustomRedirectOrigin = (uri: string) => boolean | Promise<boolean>;
export type AllowedRedirectURIs = StaticRedirectOrigin | CustomRedirectOrigin;

export interface IConsumerOptions {
  sessionRetryDelayMS: number;
  scope: string;

  callback_route?: string;
  default_callback_route?: string;
  callback_url?: string;
  allowedRedirectURIs: AllowedRedirectURIs;

  sessionOptions: SessionOptions;
  clientConfig: ModuleOptions<string>;
}

export interface ICustomSession extends Session, SessionData {
  redirect_uri: string;
  state: any;
}
