export type ContactMessage = {
  id: string;
  name: string;
  email: string;
  phone: string;
  message: string;
  createdAt: string;
  read: boolean;
  replied?: boolean;
};

export const initialMessages: ContactMessage[] = [
  {
    id: "msg-1",
    name: "Michael Roberts",
    email: "m.roberts@gmail.com",
    phone: "(732) 555-0192",
    message: "Hey Tedi, looking to book a wedding party of 4 for a private morning session in October. Do you do private group blockouts on Saturdays?",
    createdAt: "2026-08-28T14:20:00Z",
    read: false,
  },
  {
    id: "msg-2",
    name: "Anthony DeMarco",
    email: "anthony.d@outlook.com",
    phone: "(908) 555-3841",
    message: "Had a cut last Thursday, lineup was immaculate. Just wondering if you have any of the Green Flame shirts left in Size L at the studio?",
    createdAt: "2026-08-27T18:45:00Z",
    read: true,
    replied: true,
  },
  {
    id: "msg-3",
    name: "Dave Miller",
    email: "dave.miller88@yahoo.com",
    phone: "(732) 555-8910",
    message: "First time booking with you next week on Booksy. Just wanted to ask if I should wash my hair right before coming in or if you handle that in the chair?",
    createdAt: "2026-08-26T11:15:00Z",
    read: true,
  },
];

const STORAGE_KEY = "tedis_admin_messages";

export function getStoredMessages(): ContactMessage[] {
  if (typeof window === "undefined") return initialMessages;
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(initialMessages));
      return initialMessages;
    }
    return JSON.parse(raw);
  } catch {
    return initialMessages;
  }
}

export function saveContactMessage(msg: Omit<ContactMessage, "id" | "createdAt" | "read">): ContactMessage {
  const current = getStoredMessages();
  const newMsg: ContactMessage = {
    ...msg,
    id: `msg-${Date.now()}`,
    createdAt: new Date().toISOString(),
    read: false,
  };
  const updated = [newMsg, ...current];
  if (typeof window !== "undefined") {
    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    } catch (e) {
      console.warn("[messages] failed to persist:", e);
    }
  }
  return newMsg;
}

export function updateMessageStatus(id: string, updates: Partial<ContactMessage>): ContactMessage[] {
  const current = getStoredMessages();
  const updated = current.map((m) => (m.id === id ? { ...m, ...updates } : m));
  if (typeof window !== "undefined") {
    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    } catch (e) {
      console.warn("[messages] failed to persist:", e);
    }
  }
  return updated;
}

export function deleteStoredMessage(id: string): ContactMessage[] {
  const current = getStoredMessages();
  const updated = current.filter((m) => m.id !== id);
  if (typeof window !== "undefined") {
    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    } catch (e) {
      console.warn("[messages] failed to persist:", e);
    }
  }
  return updated;
}
