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

export async function signup(
  username: string,
  password: string,
  publicKey: string
) {
  const response = await fetch(`${API_BASE}/api/auth/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password, publicKey })
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Signup failed");
  }

  return response.json();
}

export async function login(username: string, password: string) {
  const response = await fetch(`${API_BASE}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
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

export async function listConversations() {
  const response = await fetch(`${API_BASE}/api/conversations`, {
    headers: {
      ...authHeaders()
    }
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Load conversations failed");
  }

  return response.json();
}

export async function createConversation(
  type: "direct" | "group" | "channel",
  name: string | null,
  members: string[]
) {
  const response = await fetch(`${API_BASE}/api/conversations`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders()
    },
    body: JSON.stringify({ type, name, members })
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Create failed");
  }

  return response.json();
}

export async function fetchMembers(conversationId: number) {
  const response = await fetch(
    `${API_BASE}/api/conversations/${conversationId}/members`,
    {
      headers: {
        ...authHeaders()
      }
    }
  );

  if (!response.ok) {
    throw new Error((await response.json()).error || "Load members failed");
  }

  return response.json();
}

export async function sendMessage(
  conversationId: number,
  payloads: Array<{
    messageId: string;
    toUsername: string;
    ciphertext: string;
    nonce: string;
  }>
) {
  const response = await fetch(`${API_BASE}/api/messages/send`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders()
    },
    body: JSON.stringify({ conversationId, payloads })
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

export async function pollSentStatuses(since: number) {
  const response = await fetch(
    `${API_BASE}/api/messages/sent?since=${since}`,
    {
      headers: {
        ...authHeaders()
      }
    }
  );

  if (!response.ok) {
    throw new Error((await response.json()).error || "Status poll failed");
  }

  return response.json();
}

export async function markRead(conversationId: number) {
  const response = await fetch(`${API_BASE}/api/messages/read`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders()
    },
    body: JSON.stringify({ conversationId })
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Read update failed");
  }

  return response.json();
}

export async function deleteMessage(payload: {
  scope: "self" | "all";
  messageId?: number;
  groupId?: string;
}) {
  const response = await fetch(`${API_BASE}/api/messages/delete`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders()
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Delete failed");
  }

  return response.json();
}

export async function setTyping(conversationId: number, isTyping: boolean) {
  const response = await fetch(`${API_BASE}/api/typing`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders()
    },
    body: JSON.stringify({ conversationId, isTyping })
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Typing update failed");
  }

  return response.json();
}

export async function fetchTyping(conversationId: number) {
  const response = await fetch(
    `${API_BASE}/api/typing?conversationId=${conversationId}`,
    {
      headers: {
        ...authHeaders()
      }
    }
  );

  if (!response.ok) {
    throw new Error((await response.json()).error || "Typing load failed");
  }

  return response.json();
}
