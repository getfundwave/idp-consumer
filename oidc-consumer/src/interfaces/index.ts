import session, { Session, SessionData, SessionOptions } from "express-session";
import { ModuleOptions } from "simple-oauth2";

export interface IConsumerOptions {
  scope: string;

  callback_route?: string;
  default_callback_route?: string;
  callback_url?: string;

  clientConfig: ModuleOptions<string>;
}

export interface IConsumerOptionsWithSessionConfig extends IConsumerOptions {
  sessionOptions: SessionOptions;
}

export interface IConsumerOptionsWithSession extends IConsumerOptions {
  session: typeof session;
}

export interface ICustomSession extends Session, SessionData {
  redirect_uri: string;
  state: any;
}
