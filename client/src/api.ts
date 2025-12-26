const API_BASE = "http://localhost:3001";

let authToken: string | null = null;

export function setAuthToken(token: string | null): void {
  authToken = token;
}

function authHeaders(): HeadersInit {
  if (!authToken) {
    return {};
  }
  return { Authorization: `Bearer ${authToken}` };
}

export async function signup(username: string, publicKey: string) {
  const response = await fetch(`${API_BASE}/api/auth/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, publicKey })
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Signup failed");
  }

  return response.json();
}

export async function login(username: string) {
  const response = await fetch(`${API_BASE}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username })
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Login failed");
  }

  return response.json();
}

export async function fetchPublicKey(username: string) {
  const response = await fetch(`${API_BASE}/api/users/${username}/public-key`);
  if (!response.ok) {
    throw new Error((await response.json()).error || "User not found");
  }
  return response.json();
}

export async function sendMessage(
  toUsername: string,
  ciphertext: string,
  nonce: string
) {
  const response = await fetch(`${API_BASE}/api/messages/send`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders()
    },
    body: JSON.stringify({ toUsername, ciphertext, nonce })
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Send failed");
  }

  return response.json();
}

export async function pollMessages(since: number) {
  const response = await fetch(`${API_BASE}/api/messages/poll?since=${since}`, {
    headers: {
      ...authHeaders()
    }
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Poll failed");
  }

  return response.json();
}
