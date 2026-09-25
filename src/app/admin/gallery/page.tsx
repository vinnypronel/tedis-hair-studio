"use client";

import Link from "next/link";
import Image from "next/image";
import { useState, useRef } from "react";
import { BearLogo } from "@/components/site/bear-logo";
import { AdminAuthGate, AdminLogoutLink } from "../admin-session";
import { galleryImages } from "@/lib/data/gallery";

type UploadState = "idle" | "preview" | "uploading" | "success";

type GalleryCategory = "cuts" | "studio";

export default function AdminGalleryPage() {
  const [state, setState] = useState<UploadState>("idle");
  const [preview, setPreview] = useState<string | null>(null);
  const [isVideo, setIsVideo] = useState(false);
  const [fileName, setFileName] = useState<string>("");
  const [category, setCategory] = useState<GalleryCategory>("cuts");
  const [altText, setAltText] = useState<string>("");
  const [featured, setFeatured] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setFileName(file.name);
    const video = file.type.startsWith("video/") || file.name.endsWith(".mp4") || file.name.endsWith(".mov");
    setIsVideo(video);

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

    // Simulate upload + gallery staging
    console.log("[Gallery Upload] Staging entry:", {
      fileName,
      category,
      type: isVideo ? "video" : "image",
      alt: altText,
      featured,
      url: `/uploads/${fileName}`,
    });

    setTimeout(() => setState("success"), 1200);
  }

  function reset() {
    setState("idle");
    setPreview(null);
    setIsVideo(false);
    setFileName("");
    setAltText("");
    setFeatured(false);
    if (fileRef.current) fileRef.current.value = "";
  }

  return (
    <AdminAuthGate>
      <div className="min-h-svh bg-stone-100 pb-20">
        {/* Admin header */}
        <header className="bg-forest-deep text-cream sticky top-0 z-40 shadow-sm">
          <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
            <div className="flex items-center gap-3">
              <BearLogo size={32} className="text-cream" />
              <span className="font-display tracking-tight">Studio Admin</span>
              <span className="mono-micro ml-3 border-[0.5px] border-neon/60 px-2 py-0.5 text-neon">
                Gallery Hub
              </span>
            </div>
            <div className="flex items-center gap-6">
              <Link href="/admin/dashboard" className="mono-micro text-cream/70 hover:text-cream">
                ← Dashboard
              </Link>
              <AdminLogoutLink className="mono-micro text-cream/70 hover:text-cream" />
            </div>
          </div>
        </header>

        <div className="mx-auto max-w-2xl px-6 py-10">
          <p className="eyebrow text-stone-500">Gallery Management</p>
          <h1 className="heading-1 mt-3">Upload a Photo or Video Reel</h1>
          <p className="mt-3 text-sm text-stone-600">
            Upload client cut portraits, video clips (.mp4, .mov), or studio atmosphere shots. Media is auto-formatted for the grid and lightbox.
          </p>

          {state === "success" ? (
            <div className="hairline-strong mt-10 bg-cream p-8 text-center">
              <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-forest/10">
                <span className="text-2xl text-forest">✓</span>
              </div>
              <h2 className="font-display mt-6 text-2xl tracking-tight">
                {isVideo ? "Video Reel Staged" : "Photo Staged for Gallery"}
              </h2>
              <p className="mt-3 text-sm text-stone-500">
                Media successfully staged. It will appear on the live gallery grid upon saving.
              </p>
              <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:justify-center">
                <button
                  onClick={reset}
                  className="cursor-pointer rounded-[2px] bg-forest px-6 py-3 text-sm font-medium text-cream transition-colors hover:bg-forest-deep"
                >
                  Upload Another
                </button>
                <Link
                  href="/gallery"
                  target="_blank"
                  className="cursor-pointer rounded-[2px] border-[0.5px] border-stone-300 px-6 py-3 text-center text-sm font-medium text-stone-700 transition-colors hover:bg-stone-200"
                >
                  View Live Gallery ↗
                </Link>
              </div>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="mt-10 flex flex-col gap-8">
              {/* File picker */}
              <div>
                <input
                  ref={fileRef}
                  id="media-upload"
                  type="file"
                  accept="image/*,video/*,.mp4,.mov"
                  onChange={handleFile}
                  className="sr-only"
                />
                {!preview ? (
                  <label
                    htmlFor="media-upload"
                    className="flex min-h-[220px] cursor-pointer flex-col items-center justify-center gap-4 rounded-[2px] border-[0.5px] border-dashed border-stone-400 bg-cream text-center transition-colors hover:border-forest hover:bg-stone-50 active:bg-stone-100"
                  >
                    <div className="flex h-14 w-14 items-center justify-center rounded-full bg-stone-200">
                      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-stone-600">
                        <path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/>
                        <circle cx="12" cy="13" r="4"/>
                      </svg>
                    </div>
                    <div>
                      <p className="font-medium text-stone-800">Tap to upload a photo or video reel</p>
                      <p className="mt-1 text-xs text-stone-500">Supports JPG, PNG, MP4, MOV videos</p>
                    </div>
                  </label>
                ) : (
                  <div className="relative">
                    <div className="hairline relative aspect-[4/5] max-h-[420px] overflow-hidden bg-stone-100 mx-auto rounded">
                      {isVideo ? (
                        <video
                          src={preview}
                          controls
                          autoPlay
                          muted
                          playsInline
                          className="h-full w-full object-contain"
                        />
                      ) : (
                        <Image src={preview} alt="Upload preview" fill className="object-cover" />
                      )}
                    </div>
                    <button
                      type="button"
                      onClick={reset}
                      className="cursor-pointer absolute top-3 right-3 flex h-8 w-8 items-center justify-center rounded-full bg-ink/70 text-cream backdrop-blur-sm transition-colors hover:bg-ink"
                    >
                      ✕
                    </button>
                    <label
                      htmlFor="media-upload"
                      className="mono-micro mt-2 block cursor-pointer text-center text-stone-500 hover:text-forest"
                    >
                      Change media file ({fileName})
                    </label>
                  </div>
                )}
              </div>

              {/* Metadata fields */}
              {preview && (
                <>
                  {/* Category */}
                  <div>
                    <p className="eyebrow mb-3 text-stone-500">Gallery Tab</p>
                    <div className="flex gap-3">
                      {(["cuts", "studio"] as GalleryCategory[]).map((cat) => (
                        <button
                          key={cat}
                          type="button"
                          onClick={() => setCategory(cat)}
                          className={`cursor-pointer flex-1 rounded-[2px] border py-3 text-sm font-medium capitalize transition-colors ${
                            category === cat
                              ? "border-forest bg-forest text-cream"
                              : "border-stone-300 bg-cream text-stone-700 hover:border-stone-500"
                          }`}
                        >
                          {cat === "cuts" ? "The Work (Cuts)" : "The Studio (Atmosphere)"}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Alt text */}
                  <div>
                    <label htmlFor="alt-text" className="eyebrow text-stone-500">
                      Description / Caption <span className="text-ember">*</span>
                    </label>
                    <input
                      id="alt-text"
                      type="text"
                      value={altText}
                      onChange={(e) => setAltText(e.target.value)}
                      placeholder={isVideo ? "e.g. Low skin taper fade reel" : "e.g. Skin fade with textured top"}
                      className="input-line mt-2 bg-white rounded border border-stone-300 px-3 py-2 text-sm text-stone-900 w-full"
                      required
                    />
                    <p className="mt-1 text-xs text-stone-400">Used as accessibility alt text and gallery tooltip</p>
                  </div>

                  {/* Featured toggle */}
                  <div className="flex items-center justify-between rounded-[2px] border border-stone-200 bg-cream px-5 py-4">
                    <div>
                      <p className="text-sm font-medium">Feature on Homepage</p>
                      <p className="mt-0.5 text-xs text-stone-500">Includes in the continuous homepage marquee carousel</p>
                    </div>
                    <button
                      type="button"
                      role="switch"
                      aria-checked={featured}
                      onClick={() => setFeatured((v) => !v)}
                      className={`cursor-pointer relative h-6 w-11 rounded-full transition-colors ${
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
                    className="cursor-pointer rounded-[2px] bg-forest py-4 text-sm font-medium text-cream shadow transition-colors hover:bg-forest-deep disabled:opacity-40"
                  >
                    {state === "uploading" ? "Uploading Media…" : isVideo ? "Add Video Reel to Gallery" : "Add Photo to Gallery"}
                  </button>
                </>
              )}
            </form>
          )}

          {/* Current Gallery Overview */}
          <div className="mt-16 border-t border-stone-200 pt-8">
            <div className="flex items-baseline justify-between">
              <h2 className="font-display text-xl tracking-tight">Active Gallery Items ({galleryImages.length})</h2>
              <Link href="/gallery" target="_blank" className="mono-micro text-forest hover:underline">
                View Live Gallery ↗
              </Link>
            </div>
            <div className="mt-4 grid grid-cols-4 gap-2 sm:grid-cols-6">
              {galleryImages.map((img) => (
                <div key={img.id} className="relative aspect-square overflow-hidden rounded bg-stone-200">
                  {img.type === "video" ? (
                    <video src={img.url} className="h-full w-full object-cover" muted />
                  ) : (
                    <Image src={img.url} alt={img.alt} fill className="object-cover" sizes="100px" />
                  )}
                  {img.type === "video" && (
                    <span className="absolute bottom-1 right-1 rounded bg-black/70 px-1 py-0.5 text-[8px] font-mono text-cream">
                      ▶
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </AdminAuthGate>
  );
}
