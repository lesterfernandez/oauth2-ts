import { Request, Response, NextFunction } from "express";
import oauthService, { IdTokenPayload } from "@/services/oauth.js";

type OAuthSuccessCallback = {
  req: Request;
  res: Response;
  data: IdTokenPayload;
};

type OAuthFailureCallback = {
  req: Request;
  res: Response;
  error: Error;
};

type Provider = {
  onSuccess: (successCallback: OAuthSuccessCallback) => void | Promise<void>;
  onFailure: (errorCallback: OAuthFailureCallback) => void;
  clientSecret: string;
  baseUrl: string;
};

class OAuth {
  private _providers: Record<string, Provider>;

  constructor() {
    this._providers = {};
  }

  setupProvider(provider: string, { baseUrl, clientSecret, onSuccess, onFailure }: Provider) {
    this._providers[provider] = {
      baseUrl,
      clientSecret,
      onSuccess,
      onFailure,
    };
  }

  authenticate(provider: string) {
    if (!this._providers[provider]) {
      throw new Error(`Provider ${provider} has not been set`);
    }
    const { onSuccess, onFailure, clientSecret, baseUrl } = this._providers[provider];

    return (req: Request, res: Response, next: NextFunction) => {
      const requiredFields = ["code", "client_id", "redirect_uri", "grant_type"];
      for (const field of requiredFields) {
        if (!req.body[field] || typeof req.body[field] !== "string") {
          const error = new Error(`Missing field: ${field}`);
          return onFailure({ req, res, error });
        }
      }

      const { code, grant_type, redirect_uri, client_id } = req.body;
      oauthService
        .exchangeCode(baseUrl, code, grant_type, client_id, redirect_uri, clientSecret)
        .then(data => onSuccess({ req, res, data: data as IdTokenPayload }))
        .catch(err => onFailure({ req, res, error: err as Error }))
        .finally(() => next);
    };
  }
}

export default OAuth;
