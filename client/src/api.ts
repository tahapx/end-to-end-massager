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
  phone: string,
  firstName: string,
  lastName: string,
  username: string,
  password: string | null,
  publicKey: string,
  deviceId: string,
  deviceName: string,
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
    body: JSON.stringify({
      phone,
      firstName,
      lastName,
      username,
      password,
      publicKey,
      deviceId,
      deviceName,
      deviceInfo
    })
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Signup failed");
  }

  return response.json();
}

export async function login(
  phone: string,
  password: string,
  deviceId: string,
  deviceName: string,
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
    body: JSON.stringify({
      phone,
      password,
      deviceId,
      deviceName,
      deviceInfo
    })
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
  const response = await fetch(
    `${API_BASE}/api/users/${username}/profile-private`,
    {
      headers: {
        ...authHeaders()
      }
    }
  );
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
  privacy?: Partial<{
    hide_online: boolean;
    hide_last_seen: boolean;
    hide_profile_photo: boolean;
    disable_read_receipts: boolean;
    disable_typing_indicator: boolean;
  }>;
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

export async function publishKeyBundle(payload: {
  identityKey: string;
  registrationId: number;
  deviceId: number;
  sessionDeviceId: string;
  signedPreKeyId: number;
  signedPreKey: string;
  signedPreKeySig: string;
  oneTimePreKeys: Array<{ id: number; key: string }>;
}) {
  const response = await fetch(`${API_BASE}/api/keys/publish`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders()
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Key publish failed");
  }

  return response.json();
}

export async function fetchKeyBundle(username: string) {
  const response = await fetch(`${API_BASE}/api/keys/bundle/${username}`);
  if (!response.ok) {
    throw new Error((await response.json()).error || "Key bundle unavailable");
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
  members: string[],
  visibility: "public" | "private" | null = null
) {
  const response = await fetch(`${API_BASE}/api/conversations`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders()
    },
    body: JSON.stringify({
      type,
      name,
      members,
      ...(visibility ? { visibility } : {})
    })
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Create failed");
  }

  return response.json();
}

export async function fetchRoster(conversationId: number) {
  const response = await fetch(
    `${API_BASE}/api/conversations/${conversationId}/roster`,
    {
      headers: {
        ...authHeaders()
      }
    }
  );
  if (!response.ok) {
    throw new Error((await response.json()).error || "Roster load failed");
  }
  return response.json();
}

export async function addConversationMember(
  conversationId: number,
  username: string
) {
  const response = await fetch(
    `${API_BASE}/api/conversations/${conversationId}/members/add`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders()
      },
      body: JSON.stringify({ username })
    }
  );
  if (!response.ok) {
    throw new Error((await response.json()).error || "Add member failed");
  }
  return response.json();
}

export async function removeConversationMember(
  conversationId: number,
  username: string
) {
  const response = await fetch(
    `${API_BASE}/api/conversations/${conversationId}/members/remove`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders()
      },
      body: JSON.stringify({ username })
    }
  );
  if (!response.ok) {
    throw new Error((await response.json()).error || "Remove member failed");
  }
  return response.json();
}

export async function updateConversationRole(
  conversationId: number,
  username: string,
  role: "admin" | "member",
  permissions?: { manage_members?: boolean; manage_invites?: boolean }
) {
  const response = await fetch(
    `${API_BASE}/api/conversations/${conversationId}/role`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders()
      },
      body: JSON.stringify({ username, role, permissions })
    }
  );
  if (!response.ok) {
    throw new Error((await response.json()).error || "Role update failed");
  }
  return response.json();
}

export async function createInviteLink(
  conversationId: number,
  maxUses: number,
  expiresInMinutes: number
) {
  const response = await fetch(
    `${API_BASE}/api/conversations/${conversationId}/invites`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders()
      },
      body: JSON.stringify({ maxUses, expiresInMinutes })
    }
  );
  if (!response.ok) {
    throw new Error((await response.json()).error || "Invite create failed");
  }
  return response.json();
}

export async function listInviteLinks(conversationId: number) {
  const response = await fetch(
    `${API_BASE}/api/conversations/${conversationId}/invites`,
    {
      headers: {
        ...authHeaders()
      }
    }
  );
  if (!response.ok) {
    throw new Error((await response.json()).error || "Invite list failed");
  }
  return response.json();
}

export async function revokeInviteLink(token: string) {
  const response = await fetch(`${API_BASE}/api/conversations/invites/revoke`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders()
    },
    body: JSON.stringify({ token })
  });
  if (!response.ok) {
    throw new Error((await response.json()).error || "Invite revoke failed");
  }
  return response.json();
}

export async function redeemInviteLink(token: string) {
  const response = await fetch(`${API_BASE}/api/invites/redeem`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders()
    },
    body: JSON.stringify({ token })
  });
  if (!response.ok) {
    throw new Error((await response.json()).error || "Invite redeem failed");
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
    toDeviceId: string;
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

export async function pollMessages(since: number, limit = 50) {
  const response = await fetch(
    `${API_BASE}/api/messages/poll?since=${since}&limit=${limit}`,
    {
    headers: {
      ...authHeaders()
    }
    }
  );

  if (!response.ok) {
    throw new Error((await response.json()).error || "Poll failed");
  }

  return response.json();
}

export async function pollSentStatuses(since: number, limit = 50) {
  const response = await fetch(
    `${API_BASE}/api/messages/sent?since=${since}&limit=${limit}`,
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

export async function fetchUserStatus(username: string) {
  const response = await fetch(`${API_BASE}/api/users/${username}/status`, {
    headers: {
      ...authHeaders()
    }
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Status load failed");
  }

  return response.json();
}

export async function updateContactPrivacy(payload: {
  username: string;
  privacy: Partial<{
    hide_online: boolean;
    hide_last_seen: boolean;
    hide_profile_photo: boolean;
    disable_read_receipts: boolean;
    disable_typing_indicator: boolean;
  }>;
}) {
  const response = await fetch(`${API_BASE}/api/privacy/contact`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders()
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Privacy update failed");
  }

  return response.json();
}

export async function enableTwoFactor(password: string) {
  const response = await fetch(`${API_BASE}/api/auth/2fa/enable`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders()
    },
    body: JSON.stringify({ password })
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Enable 2FA failed");
  }

  return response.json();
}

export async function disableTwoFactor(password: string) {
  const response = await fetch(`${API_BASE}/api/auth/2fa/disable`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders()
    },
    body: JSON.stringify({ password })
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Disable 2FA failed");
  }

  return response.json();
}

export async function listDevices() {
  const response = await fetch(`${API_BASE}/api/devices`, {
    headers: {
      ...authHeaders()
    }
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Device list failed");
  }

  return response.json();
}

export async function logoutDevice(deviceId: string) {
  const response = await fetch(`${API_BASE}/api/devices/${deviceId}/logout`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders()
    }
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Device logout failed");
  }

  return response.json();
}

export async function logoutAllDevices() {
  const response = await fetch(`${API_BASE}/api/devices/logout-all`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders()
    }
  });

  if (!response.ok) {
    throw new Error((await response.json()).error || "Logout all failed");
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
  payload: {
    banned?: boolean;
    canSend?: boolean;
    canCreate?: boolean;
    allowDirect?: boolean;
    allowGroupInvite?: boolean;
  }
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

export async function adminDownloadUserMetadata(userId: number) {
  const response = await fetch(
    `${API_BASE}/api/admin/users/${userId}/profile-json`,
    {
      headers: {
        ...adminHeaders()
      }
    }
  );
  if (!response.ok) {
    throw new Error((await response.json()).error || "Download failed");
  }
  return response.blob();
}

export async function startCall(payload: {
  callId: string;
  conversationId: number;
  toUsername: string;
  toDeviceId: string;
  media: "audio" | "video";
  offer: string;
}) {
  const response = await fetch(`${API_BASE}/api/calls/start`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders()
    },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    throw new Error((await response.json()).error || "Call start failed");
  }
  return response.json();
}

export async function answerCall(payload: { callId: string; answer: string }) {
  const response = await fetch(`${API_BASE}/api/calls/answer`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders()
    },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    throw new Error((await response.json()).error || "Call answer failed");
  }
  return response.json();
}

export async function sendIceCandidate(payload: {
  callId: string;
  candidate: string;
  target: "caller" | "callee";
}) {
  const response = await fetch(`${API_BASE}/api/calls/ice`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders()
    },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    throw new Error((await response.json()).error || "ICE send failed");
  }
  return response.json();
}

export async function endCall(payload: { callId: string }) {
  const response = await fetch(`${API_BASE}/api/calls/end`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders()
    },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    throw new Error((await response.json()).error || "Call end failed");
  }
  return response.json();
}

export async function pollCalls(since: number) {
  const response = await fetch(
    `${API_BASE}/api/calls/poll?since=${since}`,
    {
      headers: {
        ...authHeaders()
      }
    }
  );
  if (!response.ok) {
    throw new Error((await response.json()).error || "Call poll failed");
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
