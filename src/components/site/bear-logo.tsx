import { cn } from "@/lib/utils";

type BearLogoProps = {
  size?: number;
  className?: string;
  idle?: boolean;
  label?: string;
};

/**
 * The bear-and-pole mark, rendered via CSS mask so it can be tinted with
 * `currentColor`. Ink on bone, cream on forest, neon when it earns it.
 */
export function BearLogo({ size = 40, className, idle = false, label }: BearLogoProps) {
  return (
    <span
      role="img"
      aria-label={label ?? "Tedi's Hair Studio bear mark"}
      className={cn("bear-mask shrink-0", idle && "bear-idle", className)}
      style={{ width: size, height: size }}
    />
  );
}
