export type Service = {
  id: string;
  name: string;
  slug: string;
  description: string;
  durationMinutes: number;
  priceCents: number;
  active: boolean;
  mostPopular: boolean;
  sortOrder: number;
};

export const services: Service[] = [
  {
    id: "svc-basic-haircut",
    name: "Basic Haircut",
    slug: "basic-haircut",
    description:
      "The foundation. Consultation, precision cut, hot-lather neckline, styled to finish. Every cut starts with a conversation about what you actually want.",
    durationMinutes: 30,
    priceCents: 3500,
    active: true,
    mostPopular: true,
    sortOrder: 1,
  },
  {
    id: "svc-shape-up",
    name: "Shape Up",
    slug: "shape-up",
    description:
      "Hairline, temples, and neckline brought back to crisp. The maintenance visit between full cuts. In and out, sharp again.",
    durationMinutes: 30,
    priceCents: 2500,
    active: true,
    mostPopular: false,
    sortOrder: 2,
  },
  {
    id: "svc-haircut-beard",
    name: "Haircut w/ Beard",
    slug: "haircut-beard",
    description:
      "The full session. Complete cut plus beard sculpting. Lined, faded, and conditioned. The everything appointment.",
    durationMinutes: 30,
    priceCents: 4000,
    active: true,
    mostPopular: false,
    sortOrder: 3,
  },
  {
    id: "svc-shape-up-beard",
    name: "Shape Up w/ Beard",
    slug: "shape-up-beard",
    description:
      "Edges restored, beard re-lined and detailed. Keeps the last cut alive another two weeks.",
    durationMinutes: 30,
    priceCents: 3000,
    active: true,
    mostPopular: false,
    sortOrder: 4,
  },
  {
    id: "svc-beard-trim",
    name: "Beard Trim",
    slug: "beard-trim",
    description:
      "Beard only. Shaped, faded into the cheek line, finished with razor detail and oil.",
    durationMinutes: 30,
    priceCents: 2000,
    active: true,
    mostPopular: false,
    sortOrder: 5,
  },
];

export function getServiceBySlug(slug: string): Service | undefined {
  return services.find((s) => s.slug === slug);
}

export function formatPrice(cents: number): string {
  return `$${(cents / 100).toFixed(cents % 100 === 0 ? 0 : 2)}`;
}
