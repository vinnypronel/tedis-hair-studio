"use client";

import Link from "next/link";
import Image from "next/image";
import { useState, useRef } from "react";
import { BearLogo } from "@/components/site/bear-logo";

type UploadState = "idle" | "preview" | "uploading" | "success";

type GalleryCategory = "cuts" | "studio";

export default function AdminGalleryPage() {
  const [state, setState] = useState<UploadState>("idle");
  const [preview, setPreview] = useState<string | null>(null);
  const [fileName, setFileName] = useState<string>("");
  const [category, setCategory] = useState<GalleryCategory>("cuts");
  const [altText, setAltText] = useState<string>("");
  const [featured, setFeatured] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (ev) => {
      setPreview(ev.target?.result as string);
      setState("preview");
    };
    reader.readAsDataURL(file);
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!preview || !altText.trim()) return;
    setState("uploading");

    // Demo: simulate upload + gallery entry creation
    console.log("[Gallery Upload] Staging entry:", {
      fileName,
      category,
      alt: altText,
      featured,
      url: `/images/${fileName}`,
    });

    setTimeout(() => setState("success"), 1200);
  }

  function reset() {
    setState("idle");
    setPreview(null);
    setFileName("");
    setAltText("");
    setFeatured(false);
    if (fileRef.current) fileRef.current.value = "";
  }

  return (
    <div className="min-h-svh bg-stone-100">
      {/* Admin header */}
      <header className="bg-forest-deep text-cream">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <BearLogo size={32} className="text-cream" />
            <span className="font-display tracking-tight">Studio Admin</span>
            <span className="mono-micro ml-3 border-[0.5px] border-neon/60 px-2 py-0.5 text-neon">
              Demo preview
            </span>
          </div>
          <div className="flex items-center gap-6">
            <Link href="/admin/dashboard" className="mono-micro text-cream/60 hover:text-cream">
              ← Dashboard
            </Link>
            <Link href="/admin" className="mono-micro text-cream/60 hover:text-cream">
              Log out
            </Link>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-2xl px-6 py-10">
        <p className="eyebrow text-stone-500">Gallery</p>
        <h1 className="heading-1 mt-3">Upload a photo</h1>
        <p className="mt-3 text-sm text-stone-500">
          Pick from your camera roll or take a new shot. Images are auto-formatted for the gallery grid.
        </p>

        {state === "success" ? (
          <div className="mt-10 hairline-strong bg-cream p-8 text-center">
            <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-forest/10">
              <span className="text-2xl text-forest">✓</span>
            </div>
            <h2 className="font-display mt-6 text-2xl tracking-tight">Staged for gallery</h2>
            <p className="mt-3 text-sm text-stone-500">
              Once the backend is live, this image will be saved and appear in the gallery automatically.
            </p>
            <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:justify-center">
              <button
                onClick={reset}
                className="rounded-[2px] bg-forest px-6 py-3 text-sm font-medium text-cream transition-colors hover:bg-forest-deep"
              >
                Upload another
              </button>
              <Link
                href="/gallery"
                target="_blank"
                className="rounded-[2px] border-[0.5px] border-stone-300 px-6 py-3 text-center text-sm font-medium text-stone-700 transition-colors hover:bg-stone-200"
              >
                View gallery ↗
              </Link>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="mt-10 flex flex-col gap-8">
            {/* File picker — full-width tap target on mobile */}
            <div>
              <input
                ref={fileRef}
                id="photo-upload"
                type="file"
                accept="image/*"
                capture="environment"
                onChange={handleFile}
                className="sr-only"
              />
              {!preview ? (
                <label
                  htmlFor="photo-upload"
                  className="flex min-h-[200px] cursor-pointer flex-col items-center justify-center gap-4 rounded-[2px] border-[0.5px] border-dashed border-stone-300 bg-cream text-center transition-colors hover:border-forest hover:bg-stone-50 active:bg-stone-100"
                >
                  <div className="flex h-14 w-14 items-center justify-center rounded-full bg-stone-100">
                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-stone-500">
                      <path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/>
                      <circle cx="12" cy="13" r="4"/>
                    </svg>
                  </div>
                  <div>
                    <p className="font-medium text-stone-700">Tap to open camera roll</p>
                    <p className="mt-1 text-xs text-stone-400">or take a new photo · JPG, PNG, HEIC</p>
                  </div>
                </label>
              ) : (
                <div className="relative">
                  <div className="hairline relative aspect-[4/5] overflow-hidden bg-stone-100">
                    <Image src={preview} alt="Upload preview" fill className="object-cover" />
                  </div>
                  <button
                    type="button"
                    onClick={reset}
                    className="absolute top-3 right-3 flex h-8 w-8 items-center justify-center rounded-full bg-ink/60 text-cream backdrop-blur-sm transition-colors hover:bg-ink/80"
                  >
                    ✕
                  </button>
                  <label
                    htmlFor="photo-upload"
                    className="mono-micro mt-2 block cursor-pointer text-center text-stone-500 hover:text-forest"
                  >
                    Change photo
                  </label>
                </div>
              )}
            </div>

            {/* Metadata fields — only shown after image is selected */}
            {preview && (
              <>
                {/* Category */}
                <div>
                  <p className="eyebrow mb-3 text-stone-500">Category</p>
                  <div className="flex gap-3">
                    {(["cuts", "studio"] as GalleryCategory[]).map((cat) => (
                      <button
                        key={cat}
                        type="button"
                        onClick={() => setCategory(cat)}
                        className={`flex-1 rounded-[2px] border-[0.5px] py-3 text-sm font-medium capitalize transition-colors ${
                          category === cat
                            ? "border-forest bg-forest text-cream"
                            : "border-stone-300 bg-cream text-stone-700 hover:border-stone-500"
                        }`}
                      >
                        {cat}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Alt text */}
                <div>
                  <label htmlFor="alt-text" className="eyebrow text-stone-500">
                    Description <span className="text-ember">*</span>
                  </label>
                  <input
                    id="alt-text"
                    type="text"
                    value={altText}
                    onChange={(e) => setAltText(e.target.value)}
                    placeholder="e.g. Skin fade with textured top"
                    className="input-line mt-2"
                    required
                  />
                  <p className="mt-1 text-xs text-stone-400">Used as alt text for accessibility</p>
                </div>

                {/* Featured toggle */}
                <div className="flex items-center justify-between rounded-[2px] border-[0.5px] border-stone-200 bg-cream px-5 py-4">
                  <div>
                    <p className="text-sm font-medium">Feature this photo</p>
                    <p className="mt-0.5 text-xs text-stone-500">Shows in home page marquee carousel</p>
                  </div>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={featured}
                    onClick={() => setFeatured((v) => !v)}
                    className={`relative h-6 w-11 rounded-full transition-colors ${
                      featured ? "bg-forest" : "bg-stone-300"
                    }`}
                  >
                    <span
                      className={`absolute top-0.5 left-0.5 h-5 w-5 rounded-full bg-white shadow transition-transform ${
                        featured ? "translate-x-5" : "translate-x-0"
                      }`}
                    />
                  </button>
                </div>

                {/* Submit */}
                <button
                  type="submit"
                  disabled={!altText.trim() || state === "uploading"}
                  className="rounded-[2px] bg-forest py-4 text-sm font-medium text-cream transition-colors hover:bg-forest-deep disabled:opacity-40"
                >
                  {state === "uploading" ? "Uploading…" : "Add to gallery"}
                </button>
              </>
            )}
          </form>
        )}

        {/* Existing gallery previews */}
        <div className="mt-16">
          <div className="flex items-baseline justify-between">
            <h2 className="font-display text-xl tracking-tight">Current gallery</h2>
            <Link href="/gallery" target="_blank" className="mono-micro text-stone-500 hover:text-forest">
              View live ↗
            </Link>
          </div>
          <p className="mt-2 text-xs text-stone-400">
            Full CRUD (delete, reorder, edit) activates on backend launch.
          </p>
        </div>
      </div>
    </div>
  );
}
