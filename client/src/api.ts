const API_BASE = "http://localhost:3001";

let authToken: string | null = null;
let adminToken: string | null = null;

export function setAuthToken(token: string | null): void {
  authToken = token;
}

export function setAdminToken(token: string | null): void {
  adminToken = token;
}

function authHeaders(): HeadersInit {
  if (!authToken) {
    return {};
  }
  return { Authorization: `Bearer ${authToken}` };
}

function adminHeaders(): HeadersInit {
  if (!adminToken) {
    return {};
  }
  return { Authorization: `Bearer ${adminToken}` };
}

export async function signup(
  username: string,
  password: string,
  publicKey: string,
  deviceInfo: {
    userAgent?: string;
    platform?: string;
    language?: string;
    deviceModel?: string;
  }
) {
  const response = await fetch(`${API_BASE}/api/auth/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password, publicKey, deviceInfo })
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Signup failed");
  }

  return response.json();
}

export async function login(
  username: string,
  password: string,
  deviceInfo: {
    userAgent?: string;
    platform?: string;
    language?: string;
    deviceModel?: string;
  }
) {
  const response = await fetch(`${API_BASE}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password, deviceInfo })
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

export async function fetchPublicProfile(username: string) {
  const response = await fetch(`${API_BASE}/api/users/${username}/profile`);
  if (!response.ok) {
    throw new Error((await response.json()).error || "Profile not available");
  }
  return response.json();
}

export async function fetchProfile() {
  const response = await fetch(`${API_BASE}/api/profile`, {
    headers: {
      ...authHeaders()
    }
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Profile load failed");
  }

  return response.json();
}

export async function updateProfile(payload: {
  avatar?: string | null;
  bio?: string;
  profilePublic?: boolean;
  allowDirect?: boolean;
  allowGroupInvite?: boolean;
}) {
  const response = await fetch(`${API_BASE}/api/profile`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders()
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Profile update failed");
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

export async function adminLogin(username: string, password: string) {
  const response = await fetch(`${API_BASE}/api/admin/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Admin login failed");
  }

  return response.json();
}

export async function adminUpdatePassword(password: string) {
  const response = await fetch(`${API_BASE}/api/admin/password`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...adminHeaders()
    },
    body: JSON.stringify({ password })
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Admin update failed");
  }

  return response.json();
}

export async function adminListUsers() {
  const response = await fetch(`${API_BASE}/api/admin/users`, {
    headers: {
      ...adminHeaders()
    }
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Admin list users failed");
  }

  return response.json();
}

export async function adminUpdateUserFlags(
  userId: number,
  payload: { banned?: boolean; canSend?: boolean; canCreate?: boolean }
) {
  const response = await fetch(`${API_BASE}/api/admin/users/${userId}/flags`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...adminHeaders()
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Admin update failed");
  }

  return response.json();
}

export async function adminResetUserPassword(userId: number, password: string) {
  const response = await fetch(`${API_BASE}/api/admin/users/${userId}/password`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...adminHeaders()
    },
    body: JSON.stringify({ password })
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Reset failed");
  }

  return response.json();
}

export async function adminDeleteUser(userId: number) {
  const response = await fetch(`${API_BASE}/api/admin/users/${userId}/delete`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...adminHeaders()
    }
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Delete failed");
  }

  return response.json();
}

export async function adminListConversations() {
  const response = await fetch(`${API_BASE}/api/admin/conversations`, {
    headers: {
      ...adminHeaders()
    }
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "List conversations failed");
  }

  return response.json();
}

export async function adminDeleteConversation(conversationId: number) {
  const response = await fetch(
    `${API_BASE}/api/admin/conversations/${conversationId}/delete`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...adminHeaders()
      }
    }
  );

  if (!response.ok) {
    throw new Error((await response.json()).error || "Delete failed");
  }

  return response.json();
}
