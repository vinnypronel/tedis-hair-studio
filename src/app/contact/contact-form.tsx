"use client";

import { useState } from "react";
import { z } from "zod";
import { Button } from "@/components/ui/button";

const messageSchema = z.object({
  name: z.string().min(2, "Your name, please"),
  email: z.string().email("That email doesn't look right"),
  phone: z.string().min(7, "Phone number, please"),
  message: z.string().min(10, "Tell us a little more"),
});

export function ContactForm() {
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [sent, setSent] = useState(false);

  function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const payload = {
      name: String(form.get("name") ?? ""),
      email: String(form.get("email") ?? ""),
      phone: String(form.get("phone") ?? ""),
      message: String(form.get("message") ?? ""),
    };
    const result = messageSchema.safeParse(payload);
    if (!result.success) {
      const errs: Record<string, string> = {};
      for (const issue of result.error.issues) {
        errs[String(issue.path[0])] = issue.message;
      }
      setErrors(errs);
      return;
    }
    setErrors({});
    console.log("[contact] message payload:", result.data);
    setSent(true);
  }

  if (sent) {
    return (
      <div className="hairline-strong bg-cream p-10 text-center">
        <p className="font-display text-3xl tracking-tight italic">Got it.</p>
        <p className="mt-3 text-sm text-stone-700">
          Tedi reads everything. You&rsquo;ll hear back within a day.
        </p>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} noValidate className="grid gap-10 md:grid-cols-2">
      <div>
        <label htmlFor="contact-name" className="eyebrow text-stone-500">
          Name
        </label>
        <input id="contact-name" name="name" className="input-line mt-2" autoComplete="name" />
        {errors.name && (
          <p role="alert" aria-live="polite" className="mt-2 text-xs text-error">
            {errors.name}
          </p>
        )}
      </div>
      <div>
        <label htmlFor="contact-email" className="eyebrow text-stone-500">
          Email
        </label>
        <input
          id="contact-email"
          name="email"
          type="email"
          className="input-line mt-2"
          autoComplete="email"
        />
        {errors.email && (
          <p role="alert" aria-live="polite" className="mt-2 text-xs text-error">
            {errors.email}
          </p>
        )}
      </div>
      <div className="md:col-span-2">
        <label htmlFor="contact-phone" className="eyebrow text-stone-500">
          Phone
        </label>
        <input
          id="contact-phone"
          name="phone"
          type="tel"
          className="input-line mt-2"
          autoComplete="tel"
        />
        {errors.phone && (
          <p role="alert" aria-live="polite" className="mt-2 text-xs text-error">
            {errors.phone}
          </p>
        )}
      </div>
      <div className="md:col-span-2">
        <label htmlFor="contact-message" className="eyebrow text-stone-500">
          Message
        </label>
        <textarea id="contact-message" name="message" rows={4} className="input-line mt-2 resize-none" />
        {errors.message && (
          <p role="alert" aria-live="polite" className="mt-2 text-xs text-error">
            {errors.message}
          </p>
        )}
      </div>
      <div>
        <Button type="submit" arrow>
          Send message
        </Button>
      </div>
    </form>
  );
}
