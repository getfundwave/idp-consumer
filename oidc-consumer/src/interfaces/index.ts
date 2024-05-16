import { Session, SessionData, SessionOptions } from "express-session";
import { ModuleOptions } from "simple-oauth2";

export interface IConsumerOptions {
  sessionRetryDelayMS: number;
  scope: string;

  callback_route?: string;
  default_callback_route?: string;
  callback_url?: string;
  allowedRedirectURIs: Array<RegExp | string>;

  sessionOptions: SessionOptions;
  clientConfig: ModuleOptions<string>;
}

export interface ICustomSession extends Session, SessionData {
  redirect_uri: string;
  state: any;
}
