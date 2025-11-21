import * as Crypto from 'expo-crypto';
import { Buffer } from 'buffer';

// Configuration Constants
export const AUTH_CONFIG = {
  CLIENT_ID: 'YOUR_CLIENT_ID',
  AUTHORIZATION_ENDPOINT: 'https://api.myim.com/oauth/authorize',
  TOKEN_ENDPOINT: 'https://api.myim.com/oauth/token',
  REDIRECT_URI: 'myimlogin://callback',
  SCOPE: 'openid profile email',
};

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  id_token?: string;
  expires_in?: number;
  token_type?: string;
}

export interface PKCEData {
  codeVerifier: string;
  codeChallenge: string;
  state: string;
}

/**
 * Helper to encode string to Base64URL (RFC 4648)
 */
function base64URLEncode(str: string): string {
  return str
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Helper to convert buffer to Base64URL
 */
function bufferToBase64Url(buffer: Uint8Array): string {
  const base64 = Buffer.from(buffer).toString('base64');
  return base64URLEncode(base64);
}

/**
 * Generates a random string for state and code_verifier
 */
function generateRandomString(length: number = 32): string {
  const randomBytes = Crypto.getRandomBytes(length);
  return bufferToBase64Url(randomBytes);
}

/**
 * Generates the S256 Code Challenge from the Code Verifier
 */
async function generateCodeChallenge(codeVerifier: string): Promise<string> {
  const hash = await Crypto.digestStringAsync(
    Crypto.CryptoDigestAlgorithm.SHA256,
    codeVerifier,
    { encoding: Crypto.CryptoEncoding.BASE64 }
  );
  return base64URLEncode(hash);
}

/**
 * Generates all necessary PKCE data
 */
export async function generatePKCEData(): Promise<PKCEData> {
  const state = generateRandomString(16);
  const codeVerifier = generateRandomString(32);
  const codeChallenge = await generateCodeChallenge(codeVerifier);

  return {
    state,
    codeVerifier,
    codeChallenge,
  };
}

/**
 * Constructs the OAuth Authorization URL
 */
export function getAuthUrl(pkceData: PKCEData): string {
  const { state, codeChallenge } = pkceData;
  const params = new URLSearchParams({
    client_id: AUTH_CONFIG.CLIENT_ID,
    redirect_uri: AUTH_CONFIG.REDIRECT_URI,
    response_type: 'code',
    scope: AUTH_CONFIG.SCOPE,
    state: state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });

  return `${AUTH_CONFIG.AUTHORIZATION_ENDPOINT}?${params.toString()}`;
}

/**
 * Exchanges the authorization code for tokens
 */
export async function exchangeToken(authCode: string, codeVerifier: string): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: authCode,
    redirect_uri: AUTH_CONFIG.REDIRECT_URI,
    client_id: AUTH_CONFIG.CLIENT_ID,
    code_verifier: codeVerifier,
  });

  const response = await fetch(AUTH_CONFIG.TOKEN_ENDPOINT, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: body.toString(),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Token exchange failed: ${response.status} ${errorText}`);
  }

  const data = await response.json();
  return data as TokenResponse;
}

/**
 * Extracts code and state from the callback URL
 */
export function parseCallbackUrl(url: string): { code: string; state: string } | null {
  try {
    const queryString = url.split('?')[1];
    if (!queryString) return null;

    const params = new URLSearchParams(queryString);
    const code = params.get('code');
    const state = params.get('state');

    if (code && state) {
      return { code, state };
    }
    return null;
  } catch (e) {
    console.error('Error parsing callback URL:', e);
    return null;
  }
}
