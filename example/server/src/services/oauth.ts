import jwt from "jsonwebtoken";

type TokenError = {
  error: string;
  error_description: string;
};

export interface TokenPayload {
  access_token: string;
  expires_in: number;
  scope: string;
  token_type: string;
  id_token: string;
}

export interface IdTokenPayload {
  iss: string;
  azp: string;
  aud: string;
  sub: string;
  email: string;
  email_verified: boolean;
  at_hash: string;
  name: string;
  picture: string;
  given_name: string;
  family_name: string;
  iat: number;
  exp: number;
}

const exchangeCode = async (
  baseUrl: string,
  code: string,
  grantType: string,
  clientId: string,
  redirectUri: string,
  clientSecret: string
): Promise<IdTokenPayload | Error> => {
  const url = new URL(baseUrl);
  url.searchParams.set("grant_type", grantType);
  url.searchParams.set("code", code);
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("client_secret", clientSecret);

  try {
    const res = await fetch(url, { method: "POST" });

    if (!res.ok) {
      const { error } = (await res.json()) as TokenError;
      throw new Error(`Token exchange error. status: ${res.status}, error: ${error}`);
    }

    const json = await res.json();
    const { id_token: idToken } = json as TokenPayload;

    const decoded = jwt.decode(idToken) as IdTokenPayload;
    return decoded;
  } catch (e) {
    if (e instanceof Error) {
      return e;
    }
    return new Error("ts-oauth: Unexpected Error");
  }
};

export default {
  exchangeCode,
};
