import { createI18n } from "vue-i18n";

export type I18nPayload = {
  locale: string;
  available_locales?: string[];
  messages: Record<string, unknown>;
};

export const i18n = createI18n<[Record<string, unknown>], string>({
  legacy: false,
  locale: "en-US",
  fallbackLocale: "en-US",
  missingWarn: false,
  fallbackWarn: false,
  messages: {
    "en-US": {},
  },
});

export function applyI18nPayload(payload: I18nPayload) {
  i18n.global.setLocaleMessage(payload.locale, payload.messages);
  const locale = i18n.global.locale as string | { value: string };
  if (typeof locale === "string") {
    i18n.global.locale = payload.locale;
  } else {
    locale.value = payload.locale;
  }
}

export async function loadInitialI18n() {
  try {
    const response = await fetch("/backend/i18n", {
      headers: { accept: "application/json" },
    });
    if (!response.ok) {
      return;
    }
    applyI18nPayload((await response.json()) as I18nPayload);
  } catch {
    // The SSE i18n event will still fill messages after the backend connects.
  }
}
