"use client";

import Link from "next/link";
import Image from "next/image";
import { useState, useEffect } from "react";
import { BearLogo } from "@/components/site/bear-logo";
import { AdminAuthGate, AdminLogoutLink } from "../admin-session";
import { content } from "@/lib/data/content";
import { services as initialServices } from "@/lib/data/services";
import { weeklyHours as initialHours, formatHour } from "@/lib/data/availability";
import { shirts as initialShirts, ShirtStatus } from "@/lib/data/shirts";
import { galleryImages } from "@/lib/data/gallery";
import {
  ContactMessage,
  getStoredMessages,
  updateMessageStatus,
  deleteStoredMessage,
} from "@/lib/data/messages";
import { cn } from "@/lib/utils";

type AdminTab = "overview" | "messages" | "hours" | "pricing" | "merch";

export default function AdminDashboardPage() {
  const [activeTab, setActiveTab] = useState<AdminTab>("overview");
  const [messages, setMessages] = useState<ContactMessage[]>([]);
  const [studioStatus, setStudioStatus] = useState<"open" | "away">("open");
  const [noticeText, setNoticeText] = useState("Studio open for regular appointments via Booksy.");
  const [hoursList, setHoursList] = useState(initialHours);
  const [servicesList, setServicesList] = useState(initialServices);
  const [shirtsList, setShirtsList] = useState(initialShirts);
  const [saveFeedback, setSaveFeedback] = useState<string | null>(null);

  useEffect(() => {
    setMessages(getStoredMessages());
  }, []);

  function triggerFeedback(msg: string) {
    setSaveFeedback(msg);
    setTimeout(() => setSaveFeedback(null), 3000);
  }

  function handleToggleRead(id: string, currentRead: boolean) {
    const updated = updateMessageStatus(id, { read: !currentRead });
    setMessages(updated);
  }

  function handleDeleteMessage(id: string) {
    if (confirm("Delete this inquiry from your inbox?")) {
      const updated = deleteStoredMessage(id);
      setMessages(updated);
      triggerFeedback("Message removed");
    }
  }

  function handleMarkReplied(id: string) {
    const updated = updateMessageStatus(id, { replied: true, read: true });
    setMessages(updated);
  }

  function handleShirtPhotoSwap(index: number, e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const copy = [...shirtsList];
      const newImages = [...copy[index].images];
      newImages[0] = {
        ...newImages[0],
        url: ev.target?.result as string,
        alt: copy[index].name,
      };
      copy[index] = { ...copy[index], images: newImages };
      setShirtsList(copy);
      triggerFeedback(`Photo swapped for ${copy[index].name}`);
    };
    reader.readAsDataURL(file);
  }

  const unreadCount = messages.filter((m) => !m.read).length;

  return (
    <AdminAuthGate>
      <div className="min-h-svh bg-stone-100 pb-20 text-stone-900">
        {/* Admin Header */}
        <header className="bg-forest-deep text-cream sticky top-0 z-40 shadow-sm">
          <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
            <div className="flex items-center gap-3">
              <BearLogo size={32} className="text-cream" />
              <span className="font-display text-lg tracking-tight">Tedi&rsquo;s Hair Studio</span>
              <span className="mono-micro ml-2 border-[0.5px] border-neon/60 px-2 py-0.5 text-neon">
                Admin Control
              </span>
            </div>
            <div className="flex items-center gap-6">
              <Link href="/" target="_blank" className="mono-micro text-cream/70 hover:text-cream">
                View Site ↗
              </Link>
              <AdminLogoutLink className="mono-micro text-cream/70 hover:text-cream" />
            </div>
          </div>

          {/* Navigation Tabs */}
          <div className="border-t border-cream/10 bg-forest/80 px-6">
            <div className="mx-auto flex max-w-7xl gap-2 overflow-x-auto py-2">
              <button
                type="button"
                onClick={() => setActiveTab("overview")}
                className={cn(
                  "cursor-pointer rounded px-4 py-2 text-sm font-medium transition-colors whitespace-nowrap",
                  activeTab === "overview"
                    ? "bg-cream text-forest-deep"
                    : "text-cream/80 hover:bg-cream/10 hover:text-cream"
                )}
              >
                Overview
              </button>

              <button
                type="button"
                onClick={() => setActiveTab("messages")}
                className={cn(
                  "cursor-pointer flex items-center gap-2 rounded px-4 py-2 text-sm font-medium transition-colors whitespace-nowrap",
                  activeTab === "messages"
                    ? "bg-cream text-forest-deep"
                    : "text-cream/80 hover:bg-cream/10 hover:text-cream"
                )}
              >
                Messages
                {unreadCount > 0 && (
                  <span className="flex size-5 items-center justify-center rounded-full bg-neon text-[11px] font-bold text-forest-deep">
                    {unreadCount}
                  </span>
                )}
              </button>

              <button
                type="button"
                onClick={() => setActiveTab("hours")}
                className={cn(
                  "cursor-pointer rounded px-4 py-2 text-sm font-medium transition-colors whitespace-nowrap",
                  activeTab === "hours"
                    ? "bg-cream text-forest-deep"
                    : "text-cream/80 hover:bg-cream/10 hover:text-cream"
                )}
              >
                Hours & Schedule
              </button>

              <button
                type="button"
                onClick={() => setActiveTab("pricing")}
                className={cn(
                  "cursor-pointer rounded px-4 py-2 text-sm font-medium transition-colors whitespace-nowrap",
                  activeTab === "pricing"
                    ? "bg-cream text-forest-deep"
                    : "text-cream/80 hover:bg-cream/10 hover:text-cream"
                )}
              >
                Services & Pricing
              </button>

              <button
                type="button"
                onClick={() => setActiveTab("merch")}
                className={cn(
                  "cursor-pointer rounded px-4 py-2 text-sm font-medium transition-colors whitespace-nowrap",
                  activeTab === "merch"
                    ? "bg-cream text-forest-deep"
                    : "text-cream/80 hover:bg-cream/10 hover:text-cream"
                )}
              >
                Merch Showcase
              </button>

              <Link
                href="/admin/gallery"
                className="cursor-pointer flex items-center gap-1 rounded px-4 py-2 text-sm font-medium text-cream/80 transition-colors hover:bg-cream/10 hover:text-cream whitespace-nowrap"
              >
                Gallery Uploader ↗
              </Link>
            </div>
          </div>
        </header>

        {/* Feedback Toast */}
        {saveFeedback && (
          <div className="fixed bottom-6 right-6 z-50 rounded bg-forest-deep px-5 py-3 text-sm text-cream shadow-2xl flex items-center gap-3">
            <span className="text-neon">✓</span>
            {saveFeedback}
          </div>
        )}

        <main className="mx-auto max-w-7xl px-6 pt-8">
          {/* ========================================================================= */}
          {/* TAB 1: OVERVIEW                                                           */}
          {/* ========================================================================= */}
          {activeTab === "overview" && (
            <div className="space-y-8">
              {/* Studio Status Card */}
              <div className="hairline-strong bg-cream p-6 md:p-8">
                <div className="flex flex-wrap items-center justify-between gap-4">
                  <div>
                    <p className="eyebrow text-stone-500">Live Studio Status</p>
                    <h2 className="font-display mt-1 text-2xl font-semibold">
                      {studioStatus === "open" ? "Studio is Open & Operating" : "Studio Notice Active"}
                    </h2>
                  </div>
                  <div className="flex items-center gap-3">
                    <button
                      type="button"
                      onClick={() => {
                        setStudioStatus("open");
                        triggerFeedback("Status set to Open");
                      }}
                      className={cn(
                        "cursor-pointer rounded-[2px] px-4 py-2 text-xs font-semibold uppercase tracking-wider transition-colors",
                        studioStatus === "open"
                          ? "bg-success text-cream"
                          : "border border-stone-300 bg-transparent text-stone-600 hover:bg-stone-200"
                      )}
                    >
                      Normal / Open
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setStudioStatus("away");
                        triggerFeedback("Status set to Away / Holiday Notice");
                      }}
                      className={cn(
                        "cursor-pointer rounded-[2px] px-4 py-2 text-xs font-semibold uppercase tracking-wider transition-colors",
                        studioStatus === "away"
                          ? "bg-amber-600 text-cream"
                          : "border border-stone-300 bg-transparent text-stone-600 hover:bg-stone-200"
                      )}
                    >
                      Holiday / Away Notice
                    </button>
                  </div>
                </div>

                <div className="mt-5 border-t border-stone-200 pt-4">
                  <label htmlFor="notice-input" className="mono-micro text-stone-500">
                    Studio Notice / Banner Message
                  </label>
                  <div className="mt-2 flex flex-col gap-3 sm:flex-row">
                    <input
                      id="notice-input"
                      type="text"
                      value={noticeText}
                      onChange={(e) => setNoticeText(e.target.value)}
                      className="input-line flex-1 rounded bg-white px-3 py-2 text-sm text-stone-900 border border-stone-300"
                    />
                    <button
                      type="button"
                      onClick={() => triggerFeedback("Notice updated")}
                      className="cursor-pointer rounded-[2px] bg-forest px-5 py-2 text-xs font-semibold text-cream transition-colors hover:bg-forest-deep"
                    >
                      Update Notice
                    </button>
                  </div>
                </div>
              </div>

              {/* Booksy Gateway */}
              <div className="hairline-strong flex flex-wrap items-center justify-between gap-5 bg-forest p-6 text-cream md:p-8">
                <div>
                  <p className="eyebrow text-cream/50">Booksy Appointments Engine</p>
                  <p className="mt-2 max-w-xl text-sm leading-relaxed text-cream/85">
                    Appointments, client scheduling, payments, and reminders run through Booksy.
                  </p>
                </div>
                <a
                  href={content.booking.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="cursor-pointer inline-flex items-center gap-2 rounded-[2px] bg-cream px-6 py-3 text-sm font-medium text-forest-deep transition-colors hover:bg-bone"
                >
                  Open Booksy Calendar ↗
                </a>
              </div>

              {/* Recent Inquiries Snapshot */}
              <div className="hairline-strong bg-cream p-6 md:p-8">
                <div className="flex items-center justify-between border-b border-stone-200 pb-4">
                  <h3 className="font-display text-xl font-semibold">Recent Client Inquiries</h3>
                  <button
                    type="button"
                    onClick={() => setActiveTab("messages")}
                    className="cursor-pointer text-xs font-semibold text-forest hover:underline"
                  >
                    View All ({messages.length}) →
                  </button>
                </div>

                <div className="mt-4 divide-y divide-stone-200">
                  {messages.slice(0, 3).map((msg) => (
                    <div key={msg.id} className="py-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-medium text-stone-900">{msg.name}</span>
                          <span className="text-stone-400">·</span>
                          <span className="font-mono text-xs text-stone-600">{msg.email}</span>
                          {!msg.read && (
                            <span className="mono-micro rounded bg-forest px-1.5 py-0.5 text-[10px] text-cream">
                              Unread
                            </span>
                          )}
                          <span className="text-stone-400">·</span>
                          <span className="text-xs text-stone-500">
                            {new Date(msg.createdAt).toLocaleDateString("en-US", {
                              month: "short",
                              day: "numeric",
                              hour: "numeric",
                              minute: "numeric",
                            })}
                          </span>
                        </div>
                        <p className="mt-1 text-sm text-stone-700 line-clamp-1">{msg.message}</p>
                      </div>

                      <div className="flex items-center gap-2 pt-2 sm:pt-0">
                        <a
                          href={`mailto:${msg.email}?subject=Re: Inquiry at Tedi's Hair Studio&body=Hi ${encodeURIComponent(
                            msg.name
                          )},%0D%0A%0D%0AThank you for reaching out to Tedi's Hair Studio.%0D%0A%0D%0A`}
                          onClick={() => handleMarkReplied(msg.id)}
                          className="cursor-pointer inline-flex items-center gap-1 rounded bg-forest px-3 py-1.5 text-xs font-medium text-cream hover:bg-forest-deep"
                        >
                          ✉ Email Respond
                        </a>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB 2: MESSAGES INBOX                                                     */}
          {/* ========================================================================= */}
          {activeTab === "messages" && (
            <div className="space-y-6">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <p className="eyebrow text-stone-500">Inbox</p>
                  <h2 className="font-display mt-1 text-3xl font-semibold tracking-tight">
                    Client Messages & Inquiries
                  </h2>
                  <p className="mt-1 text-sm text-stone-600">
                    Messages submitted through the contact page form appear here instantly.
                  </p>
                </div>
                <div className="mono-micro text-stone-500">
                  {messages.length} total · {unreadCount} unread
                </div>
              </div>

              <div className="space-y-4">
                {messages.length === 0 ? (
                  <div className="hairline-strong bg-cream p-12 text-center">
                    <p className="text-stone-500">No client messages in the inbox yet.</p>
                  </div>
                ) : (
                  messages.map((msg) => (
                    <div
                      key={msg.id}
                      className={cn(
                        "hairline-strong p-6 transition-all",
                        msg.read ? "bg-cream/70" : "bg-cream border-l-4 border-l-forest shadow-sm"
                      )}
                    >
                      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-stone-200 pb-4">
                        <div>
                          <div className="flex items-center gap-3">
                            <h3 className="font-display text-lg font-semibold text-stone-900">
                              {msg.name}
                            </h3>
                            {!msg.read && (
                              <span className="mono-micro rounded bg-forest px-2 py-0.5 text-[10px] font-bold text-cream">
                                NEW
                              </span>
                            )}
                            {msg.replied && (
                              <span className="mono-micro rounded border border-success/40 bg-success/10 px-2 py-0.5 text-[10px] text-success font-medium">
                                Replied
                              </span>
                            )}
                          </div>
                          <div className="mt-1 flex flex-wrap items-center gap-4 text-xs text-stone-600">
                            <span className="font-mono">{msg.email}</span>
                            <span>·</span>
                            <span className="font-mono">{msg.phone}</span>
                            <span>·</span>
                            <span className="text-stone-500">
                              {new Date(msg.createdAt).toLocaleDateString("en-US", {
                                month: "short",
                                day: "numeric",
                                year: "numeric",
                                hour: "numeric",
                                minute: "numeric",
                              })}
                            </span>
                          </div>
                        </div>

                        {/* Actions */}
                        <div className="flex flex-wrap items-center gap-2">
                          {/* EMAIL RESPOND BUTTON - User requested feature */}
                          <a
                            href={`mailto:${msg.email}?subject=Re: Inquiry at Tedi's Hair Studio&body=Hi ${encodeURIComponent(
                              msg.name
                            )},%0D%0A%0D%0AThank you for reaching out to Tedi's Hair Studio.%0D%0A%0D%0A`}
                            onClick={() => handleMarkReplied(msg.id)}
                            className="cursor-pointer inline-flex items-center gap-1.5 rounded-[2px] bg-forest px-4 py-2 text-xs font-semibold text-cream shadow transition-colors hover:bg-forest-deep"
                            title={`Send email response to ${msg.email}`}
                          >
                            ✉ Email Respond
                          </a>

                          <a
                            href={`tel:${msg.phone.replace(/[^0-9+]/g, "")}`}
                            className="cursor-pointer inline-flex items-center gap-1 rounded-[2px] border border-stone-300 bg-white px-3 py-2 text-xs font-medium text-stone-700 hover:bg-stone-100"
                            title="Call or SMS client"
                          >
                            📞 Call
                          </a>

                          <button
                            type="button"
                            onClick={() => handleToggleRead(msg.id, msg.read)}
                            className="cursor-pointer rounded-[2px] border border-stone-300 bg-white px-3 py-2 text-xs text-stone-700 hover:bg-stone-100"
                          >
                            {msg.read ? "Mark Unread" : "Mark Read"}
                          </button>

                          <button
                            type="button"
                            onClick={() => handleDeleteMessage(msg.id)}
                            className="cursor-pointer rounded-[2px] border border-stone-300 bg-white px-2.5 py-2 text-xs text-error hover:bg-red-50"
                            title="Delete message"
                          >
                            ✕
                          </button>
                        </div>
                      </div>

                      <div className="mt-4">
                        <p className="text-sm leading-relaxed text-stone-800 whitespace-pre-wrap">
                          {msg.message}
                        </p>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB 3: HOURS & SCHEDULE                                                   */}
          {/* ========================================================================= */}
          {activeTab === "hours" && (
            <div className="space-y-6">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <p className="eyebrow text-stone-500">Schedule</p>
                  <h2 className="font-display mt-1 text-3xl font-semibold tracking-tight">
                    Weekly Operating Hours
                  </h2>
                  <p className="mt-1 text-sm text-stone-600">
                    Changes here update the live hours displayed on the footer and contact page.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => triggerFeedback("Hours schedule saved")}
                  className="cursor-pointer rounded-[2px] bg-forest px-6 py-2.5 text-sm font-semibold text-cream shadow transition-colors hover:bg-forest-deep"
                >
                  Save Changes
                </button>
              </div>

              <div className="hairline-strong bg-cream p-6 md:p-8">
                <div className="divide-y divide-stone-200">
                  {hoursList.map((d, index) => {
                    const isClosed = !d.open || !d.close;
                    return (
                      <div
                        key={d.dayOfWeek}
                        className="py-4 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
                      >
                        <div className="w-32">
                          <span className="font-display font-medium text-stone-900">{d.label}</span>
                        </div>

                        <div className="flex flex-1 flex-wrap items-center gap-4">
                          <label className="flex items-center gap-2 cursor-pointer">
                            <input
                              type="checkbox"
                              checked={isClosed}
                              onChange={(e) => {
                                const copy = [...hoursList];
                                if (e.target.checked) {
                                  copy[index] = { ...copy[index], open: null, close: null };
                                } else {
                                  copy[index] = { ...copy[index], open: "10:00", close: "20:00" };
                                }
                                setHoursList(copy);
                              }}
                              className="size-4 cursor-pointer accent-forest"
                            />
                            <span className="text-xs font-medium text-stone-600">Closed</span>
                          </label>

                          {!isClosed && d.open && d.close && (
                            <div className="flex items-center gap-3">
                              <div className="flex items-center gap-1.5">
                                <span className="text-xs text-stone-500">Open:</span>
                                <input
                                  type="text"
                                  value={d.open}
                                  onChange={(e) => {
                                    const copy = [...hoursList];
                                    copy[index] = { ...copy[index], open: e.target.value };
                                    setHoursList(copy);
                                  }}
                                  className="w-20 rounded border border-stone-300 bg-white px-2 py-1 text-sm font-mono text-center"
                                />
                                <span className="text-xs text-stone-500">
                                  ({formatHour(d.open)})
                                </span>
                              </div>

                              <span className="text-stone-400">to</span>

                              <div className="flex items-center gap-1.5">
                                <span className="text-xs text-stone-500">Close:</span>
                                <input
                                  type="text"
                                  value={d.close}
                                  onChange={(e) => {
                                    const copy = [...hoursList];
                                    copy[index] = { ...copy[index], close: e.target.value };
                                    setHoursList(copy);
                                  }}
                                  className="w-20 rounded border border-stone-300 bg-white px-2 py-1 text-sm font-mono text-center"
                                />
                                <span className="text-xs text-stone-500">
                                  ({formatHour(d.close)})
                                </span>
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB 4: SERVICES & PRICING                                                 */}
          {/* ========================================================================= */}
          {activeTab === "pricing" && (
            <div className="space-y-6">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <p className="eyebrow text-stone-500">Menu</p>
                  <h2 className="font-display mt-1 text-3xl font-semibold tracking-tight">
                    Services & Pricing Editor
                  </h2>
                  <p className="mt-1 text-sm text-stone-600">
                    Edit pricing and descriptions for the studio menu.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => triggerFeedback("Services & pricing updated")}
                  className="cursor-pointer rounded-[2px] bg-forest px-6 py-2.5 text-sm font-semibold text-cream shadow transition-colors hover:bg-forest-deep"
                >
                  Save Pricing
                </button>
              </div>

              <div className="hairline-strong bg-cream p-6 md:p-8">
                <div className="divide-y divide-stone-200">
                  {servicesList.map((svc, index) => (
                    <div key={svc.id} className="py-6 space-y-3">
                      <div className="flex flex-wrap items-center justify-between gap-4">
                        <div className="flex items-center gap-3">
                          <input
                            type="text"
                            value={svc.name}
                            onChange={(e) => {
                              const copy = [...servicesList];
                              copy[index] = { ...copy[index], name: e.target.value };
                              setServicesList(copy);
                            }}
                            className="font-display text-xl font-semibold bg-white border border-stone-300 rounded px-3 py-1.5 text-stone-900"
                          />
                          {svc.mostPopular && (
                            <span className="mono-micro border border-forest px-2 py-0.5 text-forest text-[10px]">
                              Most booked
                            </span>
                          )}
                        </div>

                        <div className="flex items-center gap-3">
                          <span className="text-xs text-stone-500">Price ($):</span>
                          <input
                            type="number"
                            value={svc.priceCents / 100}
                            onChange={(e) => {
                              const val = parseFloat(e.target.value) || 0;
                              const copy = [...servicesList];
                              copy[index] = { ...copy[index], priceCents: Math.round(val * 100) };
                              setServicesList(copy);
                            }}
                            className="w-24 rounded border border-stone-300 bg-white px-3 py-1.5 font-mono text-base font-medium text-center"
                          />
                        </div>
                      </div>

                      <div>
                        <label className="mono-micro text-stone-500">Description</label>
                        <textarea
                          rows={2}
                          value={svc.description}
                          onChange={(e) => {
                            const copy = [...servicesList];
                            copy[index] = { ...copy[index], description: e.target.value };
                            setServicesList(copy);
                          }}
                          className="mt-1 w-full rounded border border-stone-300 bg-white p-3 text-sm text-stone-800 resize-none"
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB 5: MERCH SHOWCASE (PHOTO SWAP & WORDING EDITOR)                       */}
          {/* ========================================================================= */}
          {activeTab === "merch" && (
            <div className="space-y-6">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <p className="eyebrow text-stone-500">Studio Apparel</p>
                  <h2 className="font-display mt-1 text-3xl font-semibold tracking-tight">
                    Merch Showcase & Photo Swapper
                  </h2>
                  <p className="mt-1 text-sm text-stone-600">
                    Swap showcase photos and update shirt titles for the studio showcase.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => triggerFeedback("Merch showcase updated")}
                  className="cursor-pointer rounded-[2px] bg-forest px-6 py-2.5 text-sm font-semibold text-cream shadow transition-colors hover:bg-forest-deep"
                >
                  Save Changes
                </button>
              </div>

              <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
                {shirtsList.map((shirt, index) => (
                  <div key={shirt.id} className="hairline-strong bg-cream p-5 flex flex-col justify-between space-y-4">
                    <div className="space-y-3">
                      {/* Photo Thumbnail + Swap Action */}
                      <div className="relative aspect-[4/5] w-full overflow-hidden rounded bg-stone-200">
                        {shirt.images[0]?.url ? (
                          <Image
                            src={shirt.images[0].url}
                            alt={shirt.name}
                            fill
                            className="object-cover"
                            sizes="300px"
                          />
                        ) : (
                          <div className="flex h-full w-full items-center justify-center text-xs text-stone-400">
                            No photo
                          </div>
                        )}
                        <label
                          htmlFor={`shirt-photo-${shirt.id}`}
                          className="cursor-pointer absolute inset-x-2 bottom-2 rounded bg-ink/80 py-2 text-center text-xs font-semibold text-cream backdrop-blur-sm transition-colors hover:bg-ink"
                        >
                          📷 Swap Photo
                        </label>
                        <input
                          id={`shirt-photo-${shirt.id}`}
                          type="file"
                          accept="image/*"
                          onChange={(e) => handleShirtPhotoSwap(index, e)}
                          className="sr-only"
                        />
                      </div>

                      {/* Shirt Name & Active Status */}
                      <div className="flex items-center justify-between gap-3 pt-1">
                        <div className="flex-1">
                          <label className="mono-micro text-stone-500">Shirt Title</label>
                          <input
                            type="text"
                            value={shirt.name}
                            onChange={(e) => {
                              const copy = [...shirtsList];
                              copy[index] = { ...copy[index], name: e.target.value };
                              setShirtsList(copy);
                            }}
                            className="font-display mt-1 w-full rounded border border-stone-300 bg-white px-3 py-1.5 text-base font-semibold text-stone-900"
                          />
                        </div>
                        <span
                          className={cn(
                            "mono-micro px-2 py-1 rounded text-[10px] uppercase font-semibold shrink-0 self-end mb-1",
                            shirt.status === "for_sale"
                              ? "bg-success/15 text-success"
                              : "bg-stone-300 text-stone-700"
                          )}
                        >
                          {shirt.status === "for_sale" ? "Active" : "Archived"}
                        </span>
                      </div>
                    </div>

                    <div className="pt-3 border-t border-stone-200 flex items-center justify-between">
                      <span className="mono-micro text-stone-500">
                        Status: <span className="font-semibold text-stone-800">{shirt.status === "for_sale" ? "Featured in Showcase" : "Display Only / Past Drop"}</span>
                      </span>
                      <button
                        type="button"
                        onClick={() => {
                          const copy = [...shirtsList];
                          const nextStatus: ShirtStatus =
                            shirt.status === "for_sale" ? "display_only" : "for_sale";
                          copy[index] = { ...copy[index], status: nextStatus };
                          setShirtsList(copy);
                          triggerFeedback(`Toggled status for ${shirt.name}`);
                        }}
                        className={cn(
                          "cursor-pointer w-28 py-1.5 text-center text-xs font-semibold tracking-wide rounded-[2px] border transition-colors duration-200",
                          shirt.status === "for_sale"
                            ? "border-stone-800 bg-white text-stone-900 hover:bg-stone-100"
                            : "border-stone-300 bg-stone-200/80 text-stone-500 hover:bg-stone-300 hover:text-stone-700"
                        )}
                      >
                        {shirt.status === "for_sale" ? "Archive" : "Unarchive"}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </main>
      </div>
    </AdminAuthGate>
  );
}
