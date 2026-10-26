import crypto from 'node:crypto';
import {
  db,
  handleFirestoreError,
  OperationType,
} from '../lib/firestore-service.ts';
import {
  collection,
  doc,
  getDoc,
  getDocs,
  setDoc,
  updateDoc,
  deleteDoc,
  query,
  where,
  orderBy,
  limit,
} from 'firebase/firestore';

const AUTH_SECRET = process.env.AUTH_SECRET || 'tsw-v2-cosmic-auth-secret-key-2026';

export interface ProfileInput {
  name: string;
  avatar?: string;
  themeColor?: string;
  bio?: string;
  shortcuts?: string;
  preferences?: string;
  isDefault?: boolean;
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  try {
    const [salt, key] = storedHash.split(':');
    if (!salt || !key) return false;
    const keyBuffer = Buffer.from(key, 'hex');
    const derivedKey = crypto.scryptSync(password, salt, 64);
    return crypto.timingSafeEqual(keyBuffer, derivedKey);
  } catch {
    return false;
  }
}

export function createSessionToken(userId: number, username: string): string {
  const payload = JSON.stringify({ userId, username, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 });
  const b64 = Buffer.from(payload).toString('base64url');
  const sig = crypto.createHmac('sha256', AUTH_SECRET).update(b64).digest('base64url');
  return `${b64}.${sig}`;
}

export function verifySessionToken(token: string): { userId: number; username: string } | null {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [b64, sig] = parts;
  const expectedSig = crypto.createHmac('sha256', AUTH_SECRET).update(b64).digest('base64url');
  if (sig !== expectedSig) return null;
  try {
    const payload = JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
    if (payload.exp && Date.now() > payload.exp) return null;
    return { userId: payload.userId, username: payload.username };
  } catch {
    return null;
  }
}

let seqCounter = 0;
function nextId(): number {
  seqCounter = (seqCounter + 1) % 10000;
  return Date.now() * 100 + seqCounter;
}

const starterShortcuts = [
  { name: 'YouTube', url: 'https://www.youtube.com' },
  { name: 'TikTok', url: 'https://www.tiktok.com' },
  { name: 'Geforce Now', url: 'https://play.geforcenow.com' },
  { name: 'Roblox', url: 'https://www.roblox.com' },
  { name: 'Twitch', url: 'https://www.twitch.tv' },
  { name: 'Snapchat', url: 'https://www.snapchat.com' },
  { name: 'Instagram', url: 'https://www.instagram.com' },
  { name: 'Discord', url: 'https://discord.com/app' },
  { name: 'GTA 5', url: 'gta5://options' },
  { name: 'Movies', url: 'https://sflix.to' }
];

export async function signUpUser(username: string, password: string, email?: string) {
  const cleanUsername = username.trim();
  if (cleanUsername.length < 3) {
    throw new Error('Username must be at least 3 characters long');
  }
  if (!password || password.length < 4) {
    throw new Error('Password must be at least 4 characters long');
  }

  try {
    const usersCol = collection(db, 'users');
    const existingSnap = await getDocs(usersCol);
    const existing = existingSnap.docs.map(d => d.data());
    const isTaken = existing.some(u => (u.username || '').toLowerCase() === cleanUsername.toLowerCase());
    if (isTaken) {
      throw new Error('Username is already taken. Please choose another.');
    }

    const userId = nextId();
    const userEmail = email && email.includes('@') ? email.trim() : `${cleanUsername.toLowerCase()}@tswv2.local`;
    const uid = 'usr_' + crypto.randomBytes(8).toString('hex');
    const passwordHash = hashPassword(password);
    const createdAt = new Date().toISOString();

    const userData = {
      id: userId,
      uid,
      username: cleanUsername,
      passwordHash,
      email: userEmail,
      createdAt,
    };

    await setDoc(doc(db, 'users', String(userId)), userData);

    const profileId = nextId();
    const profileData = {
      id: profileId,
      userId,
      name: cleanUsername,
      avatar: 'astronaut',
      themeColor: '#5aa2ff',
      bio: 'Explorer of the cosmos',
      shortcuts: JSON.stringify(starterShortcuts),
      preferences: JSON.stringify({
        searchEngine: 'https://www.google.com/search?q=',
        stars: true,
        shoot: true,
        bg: 'stars'
      }),
      isDefault: true,
      createdAt,
      updatedAt: createdAt,
    };

    await setDoc(doc(db, 'profiles', String(profileId)), profileData);

    const token = createSessionToken(userId, cleanUsername);
    return {
      user: { id: userId, username: cleanUsername, email: userEmail },
      profile: profileData,
      token,
      isNewAccount: true,
    };
  } catch (error: any) {
    if (error.message && error.message.includes('already taken')) throw error;
    handleFirestoreError(error, OperationType.WRITE, 'users');
  }
}

export async function loginUser(username: string, password: string) {
  const cleanUsername = username.trim();
  if (!cleanUsername || !password) {
    throw new Error('Username and password are required');
  }

  try {
    const usersCol = collection(db, 'users');
    const snap = await getDocs(usersCol);
    const allUsers = snap.docs.map(d => d.data());
    const match = allUsers.find(u =>
      (u.username || '').toLowerCase() === cleanUsername.toLowerCase() ||
      (u.email || '').toLowerCase() === cleanUsername.toLowerCase()
    );

    if (!match || !match.passwordHash) {
      throw new Error('Invalid username or password');
    }

    const isValid = verifyPassword(password, match.passwordHash);
    if (!isValid) {
      throw new Error('Invalid username or password');
    }

    const userProfiles = await getUserProfiles(match.id);
    let activeProfile = userProfiles.find(p => p.isDefault) || userProfiles[0];
    if (!activeProfile) {
      activeProfile = await createProfile(match.id, {
        name: match.username || 'Voyager',
        avatar: 'astronaut',
        themeColor: '#5aa2ff',
        bio: 'Explorer of the cosmos',
        isDefault: true,
      });
    }

    const token = createSessionToken(match.id, match.username || match.email.split('@')[0]);
    return {
      user: { id: match.id, username: match.username || match.email.split('@')[0], email: match.email },
      profile: activeProfile,
      profiles: userProfiles,
      token,
    };
  } catch (error: any) {
    if (error.message && error.message.includes('Invalid')) throw error;
    handleFirestoreError(error, OperationType.GET, 'users');
  }
}

export async function getUserById(userId: number) {
  try {
    const snap = await getDoc(doc(db, 'users', String(userId)));
    if (!snap.exists()) return null;
    const data = snap.data();
    return {
      id: data.id,
      username: data.username,
      email: data.email,
      createdAt: data.createdAt,
    };
  } catch (error) {
    handleFirestoreError(error, OperationType.GET, `users/${userId}`);
  }
}

export async function getOrCreateUser(uid: string, email: string) {
  try {
    const usersCol = collection(db, 'users');
    const q = query(usersCol, where('uid', '==', uid));
    const snap = await getDocs(q);
    if (!snap.empty) {
      return snap.docs[0].data();
    }

    const userId = nextId();
    const createdAt = new Date().toISOString();
    const userData = {
      id: userId,
      uid,
      email,
      username: email.split('@')[0] || 'Voyager',
      createdAt,
    };

    await setDoc(doc(db, 'users', String(userId)), userData);

    const profileId = nextId();
    const profileData = {
      id: profileId,
      userId,
      name: email.split('@')[0] || 'Voyager',
      avatar: 'astronaut',
      themeColor: '#5aa2ff',
      bio: 'Explorer of the cosmos',
      shortcuts: JSON.stringify(starterShortcuts),
      preferences: JSON.stringify({
        searchEngine: 'https://www.google.com/search?q=',
        stars: true,
        shoot: true,
        bg: 'stars',
      }),
      isDefault: true,
      createdAt,
      updatedAt: createdAt,
    };

    await setDoc(doc(db, 'profiles', String(profileId)), profileData);
    return userData;
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, 'users');
  }
}

export async function getUserProfiles(userId: number) {
  try {
    const profilesCol = collection(db, 'profiles');
    const q = query(profilesCol, where('userId', '==', userId));
    const snap = await getDocs(q);
    const list = snap.docs.map(d => d.data());
    list.sort((a, b) => {
      if (a.isDefault && !b.isDefault) return -1;
      if (!a.isDefault && b.isDefault) return 1;
      return (b.createdAt || '').localeCompare(a.createdAt || '');
    });
    return list;
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, 'profiles');
  }
}

export async function getProfilesByUid(uid: string) {
  try {
    const usersCol = collection(db, 'users');
    const q = query(usersCol, where('uid', '==', uid));
    const snap = await getDocs(q);
    if (snap.empty) return [];
    const user = snap.docs[0].data();
    return await getUserProfiles(user.id);
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, 'profiles');
  }
}

export async function createProfile(userId: number, data: ProfileInput) {
  try {
    const profileId = nextId();
    const createdAt = new Date().toISOString();

    if (data.isDefault) {
      const existing = await getUserProfiles(userId);
      for (const p of existing) {
        if (p.isDefault) {
          await updateDoc(doc(db, 'profiles', String(p.id)), { isDefault: false });
        }
      }
    }

    const profileData = {
      id: profileId,
      userId,
      name: data.name.trim(),
      avatar: data.avatar || 'astronaut',
      themeColor: data.themeColor || '#5aa2ff',
      bio: data.bio || '',
      shortcuts: typeof data.shortcuts === 'string' ? data.shortcuts : JSON.stringify(data.shortcuts || []),
      preferences: typeof data.preferences === 'string' ? data.preferences : JSON.stringify(data.preferences || {}),
      isDefault: !!data.isDefault,
      createdAt,
      updatedAt: createdAt,
    };

    await setDoc(doc(db, 'profiles', String(profileId)), profileData);
    return profileData;
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, 'profiles');
  }
}

export async function updateProfile(profileId: number, userId: number, data: Partial<ProfileInput>) {
  try {
    const docRef = doc(db, 'profiles', String(profileId));
    const snap = await getDoc(docRef);
    if (!snap.exists()) return null;
    const existing = snap.data();
    if (existing.userId !== userId) return null;

    if (data.isDefault) {
      const all = await getUserProfiles(userId);
      for (const p of all) {
        if (p.id !== profileId && p.isDefault) {
          await updateDoc(doc(db, 'profiles', String(p.id)), { isDefault: false });
        }
      }
    }

    const updateData: Record<string, any> = { updatedAt: new Date().toISOString() };
    if (data.name !== undefined) updateData.name = data.name.trim();
    if (data.avatar !== undefined) updateData.avatar = data.avatar;
    if (data.themeColor !== undefined) updateData.themeColor = data.themeColor;
    if (data.bio !== undefined) updateData.bio = data.bio;
    if (data.shortcuts !== undefined) {
      updateData.shortcuts = typeof data.shortcuts === 'string' ? data.shortcuts : JSON.stringify(data.shortcuts);
    }
    if (data.preferences !== undefined) {
      updateData.preferences = typeof data.preferences === 'string' ? data.preferences : JSON.stringify(data.preferences);
    }
    if (data.isDefault !== undefined) updateData.isDefault = data.isDefault;

    await updateDoc(docRef, updateData);
    const updatedSnap = await getDoc(docRef);
    return updatedSnap.data();
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, `profiles/${profileId}`);
  }
}

export async function deleteProfile(profileId: number, userId: number) {
  try {
    const docRef = doc(db, 'profiles', String(profileId));
    const snap = await getDoc(docRef);
    if (!snap.exists()) return null;
    const existing = snap.data();
    if (existing.userId !== userId) return null;

    await deleteDoc(docRef);
    return existing;
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, `profiles/${profileId}`);
  }
}

export async function ensureChatTables() {
  return;
}

export async function searchUsers(searchTerm: string, currentUserId: number) {
  const term = searchTerm.trim().toLowerCase();
  if (!term) return [];
  try {
    const snap = await getDocs(collection(db, 'users'));
    const allUsers = snap.docs.map(d => d.data());
    const matches = allUsers
      .filter(u => u.id !== currentUserId && (u.username || '').toLowerCase().includes(term))
      .slice(0, 10);

    const friendsSnap = await getDocs(query(collection(db, 'friends'), where('userId', '==', currentUserId)));
    const friendIds = new Set(friendsSnap.docs.map(d => d.data().friendId));

    return matches.map(u => ({
      id: u.id,
      username: u.username || 'User',
      isFriend: friendIds.has(u.id),
    }));
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, 'users');
  }
}

const PROFANITY_LIST = [
  'fuck', 'shit', 'bitch', 'asshole', 'cunt', 'dick', 'pussy', 'whore', 'slut',
  'fag', 'faggot', 'nigger', 'nigga', 'retard', 'cock', 'bastard', 'nazi', 'hitler'
];

export function filterProfanity(text: string): string {
  if (!text) return '';
  let res = text;
  for (const word of PROFANITY_LIST) {
    const regex = new RegExp(`\\b${word}\\b|\\b${word}s\\b|\\b${word}ing\\b|\\b${word}ed\\b`, 'gi');
    res = res.replace(regex, (match) => '*'.repeat(match.length));
  }
  return res;
}

export async function addFriend(userId: number, targetUsername: string) {
  const cleanTarget = targetUsername.trim().replace(/^@/, '');
  try {
    const usersSnap = await getDocs(collection(db, 'users'));
    const allUsers = usersSnap.docs.map(d => d.data());
    const target = allUsers.find(u => (u.username || '').toLowerCase() === cleanTarget.toLowerCase());
    if (!target) {
      throw new Error(`User "@${cleanTarget}" not found`);
    }
    if (target.id === userId) {
      throw new Error('You cannot add yourself as a friend');
    }

    const friendsSnap = await getDocs(collection(db, 'friends'));
    const allFriends = friendsSnap.docs.map(d => ({ docId: d.id, ...d.data() }));

    const existingFromMe = allFriends.find(f => f.userId === userId && f.friendId === target.id);
    const existingToMe = allFriends.find(f => f.userId === target.id && f.friendId === userId);

    if (existingFromMe && existingFromMe.status === 'accepted') {
      return {
        id: target.id,
        friendId: target.id,
        username: target.username,
        status: 'accepted',
        isPending: false,
        message: `You are already friends with @${target.username}!`,
      };
    }

    if (existingToMe && existingToMe.status === 'pending') {
      const now = new Date().toISOString();
      await setDoc(doc(db, 'friends', `${userId}_${target.id}`), {
        id: nextId(),
        userId,
        friendId: target.id,
        status: 'accepted',
        createdAt: now,
      });
      await setDoc(doc(db, 'friends', `${target.id}_${userId}`), {
        id: nextId(),
        userId: target.id,
        friendId: userId,
        status: 'accepted',
        createdAt: now,
      });
      return {
        id: target.id,
        friendId: target.id,
        username: target.username,
        status: 'accepted',
        isPending: false,
        message: `Accepted mutual friend request with @${target.username}!`,
      };
    }

    await setDoc(doc(db, 'friends', `${userId}_${target.id}`), {
      id: nextId(),
      userId,
      friendId: target.id,
      status: 'pending',
      createdAt: new Date().toISOString(),
    });

    return {
      id: target.id,
      friendId: target.id,
      username: target.username,
      status: 'pending',
      isPending: true,
      message: `Friend request sent to @${target.username}. Awaiting approval!`,
    };
  } catch (error: any) {
    if (error.message && (error.message.includes('not found') || error.message.includes('cannot add'))) throw error;
    handleFirestoreError(error, OperationType.WRITE, 'friends');
  }
}

export async function getIncomingFriendRequests(userId: number) {
  try {
    const friendsSnap = await getDocs(collection(db, 'friends'));
    const allFriends = friendsSnap.docs.map(d => d.data());
    const pending = allFriends.filter(f => f.friendId === userId && f.status === 'pending');

    const usersSnap = await getDocs(collection(db, 'users'));
    const allUsers = new Map(usersSnap.docs.map(d => [d.data().id, d.data()]));

    return pending.map(p => {
      const sender = allUsers.get(p.userId);
      return {
        id: p.id,
        requesterId: p.userId,
        username: sender?.username || 'User',
        createdAt: p.createdAt,
      };
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, 'friends');
  }
}

export async function acceptFriendRequest(userId: number, requesterId: number) {
  try {
    const now = new Date().toISOString();
    await setDoc(doc(db, 'friends', `${userId}_${requesterId}`), {
      id: nextId(),
      userId,
      friendId: requesterId,
      status: 'accepted',
      createdAt: now,
    });
    await setDoc(doc(db, 'friends', `${requesterId}_${userId}`), {
      id: nextId(),
      userId: requesterId,
      friendId: userId,
      status: 'accepted',
      createdAt: now,
    });
    const reqUser = await getUserById(requesterId);
    return { success: true, friend: reqUser };
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, 'friends');
  }
}

export async function declineFriendRequest(userId: number, requesterId: number) {
  try {
    await deleteDoc(doc(db, 'friends', `${requesterId}_${userId}`));
    return { success: true };
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, 'friends');
  }
}

export async function removeFriend(userId: number, friendId: number) {
  try {
    await deleteDoc(doc(db, 'friends', `${userId}_${friendId}`));
    await deleteDoc(doc(db, 'friends', `${friendId}_${userId}`));
    return { success: true };
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, 'friends');
  }
}

export async function getFriendsList(userId: number) {
  try {
    const friendsSnap = await getDocs(collection(db, 'friends'));
    const accepted = friendsSnap.docs.map(d => d.data()).filter(f => f.userId === userId && f.status === 'accepted');

    const usersSnap = await getDocs(collection(db, 'users'));
    const allUsers = new Map(usersSnap.docs.map(d => [d.data().id, d.data()]));

    const profilesSnap = await getDocs(collection(db, 'profiles'));
    const defaultProfiles = new Map();
    for (const d of profilesSnap.docs) {
      const p = d.data();
      if (p.isDefault || !defaultProfiles.has(p.userId)) {
        defaultProfiles.set(p.userId, p);
      }
    }

    const messagesSnap = await getDocs(collection(db, 'messages'));
    const allMessages = messagesSnap.docs.map(d => d.data());

    return accepted.map(f => {
      const u = allUsers.get(f.friendId);
      const p = defaultProfiles.get(f.friendId);

      const dms = allMessages.filter(m =>
        (m.senderId === userId && m.receiverId === f.friendId) ||
        (m.senderId === f.friendId && m.receiverId === userId)
      ).sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));

      const last = dms[0];

      return {
        id: f.friendId,
        friendId: f.friendId,
        username: u?.username || 'Friend',
        avatar: p?.avatar || 'astronaut',
        isOnline: true,
        online: true,
        lastMessage: last?.content || null,
        lastMessageTime: last?.createdAt || null,
      };
    }).sort((a, b) => {
      if (a.lastMessageTime && b.lastMessageTime) return b.lastMessageTime.localeCompare(a.lastMessageTime);
      if (a.lastMessageTime) return -1;
      if (b.lastMessageTime) return 1;
      return a.username.localeCompare(b.username);
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, 'friends');
  }
}

export async function getDirectMessages(userId: number, friendId: number) {
  try {
    const snap = await getDocs(collection(db, 'messages'));
    const list = snap.docs.map(d => d.data());
    const filtered = list.filter(m =>
      (m.senderId === userId && m.receiverId === friendId) ||
      (m.senderId === friendId && m.receiverId === userId)
    ).sort((a, b) => (a.createdAt || '').localeCompare(b.createdAt || ''));

    return filtered.map(m => ({
      id: m.id,
      senderId: m.senderId,
      receiverId: m.receiverId,
      content: m.content,
      createdAt: m.createdAt,
      isMe: m.senderId === userId,
    }));
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, 'messages');
  }
}

export async function sendDirectMessage(senderId: number, receiverId: number, content: string) {
  const clean = filterProfanity(content.trim());
  if (!clean) throw new Error('Message content cannot be empty');

  const rec = await getUserById(receiverId);
  if (!rec) throw new Error('Recipient user not found');

  try {
    const msgId = nextId();
    const createdAt = new Date().toISOString();
    const msgData = {
      id: msgId,
      senderId,
      receiverId,
      content: clean,
      createdAt,
      isRead: false,
    };
    await setDoc(doc(db, 'messages', String(msgId)), msgData);
    return {
      id: msgId,
      senderId,
      receiverId,
      content: clean,
      createdAt,
      isMe: true,
    };
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, 'messages');
  }
}

export async function deleteDirectMessage(userId: number, messageId: number) {
  try {
    const docRef = doc(db, 'messages', String(messageId));
    const snap = await getDoc(docRef);
    if (snap.exists() && snap.data().senderId === userId) {
      await deleteDoc(docRef);
    }
    return { success: true };
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, `messages/${messageId}`);
  }
}

export async function editDirectMessage(userId: number, messageId: number, content: string) {
  const clean = filterProfanity(content.trim());
  if (!clean) throw new Error('Content cannot be empty');

  try {
    const docRef = doc(db, 'messages', String(messageId));
    const snap = await getDoc(docRef);
    if (snap.exists() && snap.data().senderId === userId) {
      await updateDoc(docRef, { content: clean });
    }
    return { success: true, content: clean };
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, `messages/${messageId}`);
  }
}

export async function getPublicMessages(channel: string) {
  const cleanChannel = ['chat-1', 'chat-2', 'announcements'].includes(channel) ? channel : 'chat-1';

  try {
    const snap = await getDocs(collection(db, 'publicMessages'));
    let messages = snap.docs.map(d => d.data()).filter(m => m.channel === cleanChannel);

    if (cleanChannel === 'announcements' && messages.length === 0) {
      const msgId = nextId();
      const defaultAnnouncement = {
        id: msgId,
        channel: 'announcements',
        userId: 1,
        username: 'TSW Official',
        avatar: 'lightning',
        content: '📢 Welcome to TSW v2 Public Channels! You can chat freely with members in #chat-1 and #chat-2. All messages in public rooms automatically expire after 7 days.',
        createdAt: new Date().toISOString(),
      };
      await setDoc(doc(db, 'publicMessages', String(msgId)), defaultAnnouncement);
      messages = [defaultAnnouncement];
    }

    const usersSnap = await getDocs(collection(db, 'users'));
    const allUsers = new Map(usersSnap.docs.map(d => [d.data().id, d.data()]));

    const profilesSnap = await getDocs(collection(db, 'profiles'));
    const defaultProfiles = new Map();
    for (const d of profilesSnap.docs) {
      const p = d.data();
      if (p.isDefault || !defaultProfiles.has(p.userId)) {
        defaultProfiles.set(p.userId, p);
      }
    }

    messages.sort((a, b) => (a.createdAt || '').localeCompare(b.createdAt || ''));

    return messages.map(m => {
      const u = allUsers.get(m.userId);
      const p = defaultProfiles.get(m.userId);
      return {
        id: m.id,
        channel: m.channel,
        userId: m.userId,
        username: m.username || u?.username || 'Member',
        avatar: m.avatar || p?.avatar || 'astronaut',
        content: m.content,
        createdAt: m.createdAt,
      };
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, 'publicMessages');
  }
}

export async function sendPublicMessage(channel: string, userId: number, content: string) {
  const cleanChannel = ['chat-1', 'chat-2', 'announcements'].includes(channel) ? channel : 'chat-1';
  const cleanContent = filterProfanity((content || '').trim());
  if (!cleanContent) {
    throw new Error('Message content cannot be empty');
  }

  if (cleanChannel === 'announcements') {
    const user = await getUserById(userId);
    const username = (user?.username || '').toLowerCase();
    const isAdmin = username.includes('admin') || username.includes('tsw') || username.includes('alex');
    if (!isAdmin) {
      throw new Error('Announcements is a read-only channel. Only administrators can post announcements.');
    }
  }

  try {
    const user = await getUserById(userId);
    const profilesList = await getUserProfiles(userId);
    const activeProfile = profilesList.find(p => p.isDefault) || profilesList[0];

    const msgId = nextId();
    const createdAt = new Date().toISOString();
    const msgData = {
      id: msgId,
      channel: cleanChannel,
      userId,
      username: user?.username || 'Member',
      avatar: activeProfile?.avatar || 'astronaut',
      content: cleanContent,
      createdAt,
    };

    await setDoc(doc(db, 'publicMessages', String(msgId)), msgData);
    return msgData;
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, 'publicMessages');
  }
}

export async function deletePublicMessage(userId: number, messageId: number, isAdmin: boolean) {
  try {
    const docRef = doc(db, 'publicMessages', String(messageId));
    const snap = await getDoc(docRef);
    if (!snap.exists()) return { success: true };
    const msg = snap.data();
    if (isAdmin || msg.userId === userId) {
      await deleteDoc(docRef);
    }
    return { success: true };
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, `publicMessages/${messageId}`);
  }
}

export async function editPublicMessage(userId: number, messageId: number, content: string) {
  const clean = filterProfanity((content || '').trim());
  if (!clean) throw new Error('Message content cannot be empty');

  try {
    const docRef = doc(db, 'publicMessages', String(messageId));
    const snap = await getDoc(docRef);
    if (snap.exists() && snap.data().userId === userId) {
      await updateDoc(docRef, { content: clean });
    }
    return { success: true, content: clean };
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, `publicMessages/${messageId}`);
  }
}
