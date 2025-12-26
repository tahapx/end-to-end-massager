import fs from "node:fs";
import path from "node:path";

const PROFILE_DIR = path.join(process.cwd(), "profiles");

export type ProfileEntry = {
  ip: string;
  userAgent: string;
  platform: string;
  language: string;
  deviceModel: string;
  at: number;
};

export type UserProfile = {
  username: string;
  last_ip: string;
  last_user_agent: string;
  last_platform: string;
  last_language: string;
  last_device_model: string;
  last_seen_at: number;
  history: ProfileEntry[];
};

function ensureDir(): void {
  if (!fs.existsSync(PROFILE_DIR)) {
    fs.mkdirSync(PROFILE_DIR, { recursive: true });
  }
}

function profilePath(username: string): string {
  const safe = username.replace(/[^a-zA-Z0-9_-]/g, "_");
  return path.join(PROFILE_DIR, `${safe}.json`);
}

export function updateUserProfile(
  username: string,
  ip: string,
  info: {
    userAgent?: string;
    platform?: string;
    language?: string;
    deviceModel?: string;
  }
): void {
  ensureDir();
  const filePath = profilePath(username);
  let existing: UserProfile | null = null;

  if (fs.existsSync(filePath)) {
    try {
      existing = JSON.parse(fs.readFileSync(filePath, "utf-8")) as UserProfile;
    } catch {
      existing = null;
    }
  }

  const entry: ProfileEntry = {
    ip,
    userAgent: info.userAgent || "",
    platform: info.platform || "",
    language: info.language || "",
    deviceModel: info.deviceModel || "",
    at: Date.now()
  };

  const history = existing?.history || [];
  history.push(entry);
  const trimmed = history.slice(-20);

  const profile: UserProfile = {
    username,
    last_ip: entry.ip,
    last_user_agent: entry.userAgent,
    last_platform: entry.platform,
    last_language: entry.language,
    last_device_model: entry.deviceModel,
    last_seen_at: entry.at,
    history: trimmed
  };

  fs.writeFileSync(filePath, JSON.stringify(profile, null, 2));
}

export function readUserProfile(username: string): UserProfile | null {
  ensureDir();
  const filePath = profilePath(username);
  if (!fs.existsSync(filePath)) {
    return null;
  }
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf-8")) as UserProfile;
  } catch {
    return null;
  }
}
