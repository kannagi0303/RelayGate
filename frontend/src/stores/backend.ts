import { defineStore } from "pinia";
import { connectBackendEvents } from "@/lib/backendEvents";
import { applyI18nPayload, type I18nPayload } from "@/plugins/i18n";
import { postBackendAction, type ActionFeedback } from "@/lib/actions";

export type BackendEnvelope =
  | { event: "backend_full"; payload: unknown }
  | { event: "i18n_full"; payload: I18nPayload }
  | { event: string; payload: unknown };

let feedbackTimer: ReturnType<typeof setTimeout> | null = null;

export const useBackendStore = defineStore("backend", {
  state: () => ({
    connected: false,
    lastEventName: "",
    backendPayload: null as any,
    i18nLocale: "en-US",
    feedback: null as ActionFeedback | null,
    actionBusy: false,
  }),
  getters: {
    payload: (state) => state.backendPayload as any,
    status: (state) => state.backendPayload?.status ?? null,
    settings: (state) => state.backendPayload?.settings ?? null,
    traffic: (state) => state.backendPayload?.traffic ?? null,
    patch: (state) => state.backendPayload?.patch ?? null,
    render: (state) => state.backendPayload?.render ?? null,
    adblock: (state) => state.backendPayload?.adblock ?? null,
    resourceReplace: (state) => state.backendPayload?.resource_replace ?? null,
    userScript: (state) => state.backendPayload?.user_script ?? null,
    gateway: (state) => state.backendPayload?.gateway ?? null,
    upstreams: (state) => state.backendPayload?.upstreams ?? null,
    upstreamRoutes: (state) => state.backendPayload?.upstream_routes ?? null,
    dns: (state) => state.backendPayload?.dns ?? null,
  },
  actions: {
    connect() {
      connectBackendEvents({
        onOpen: () => {
          this.connected = true;
        },
        onClose: () => {
          this.connected = false;
        },
        onMessage: (eventName, data) => {
          this.lastEventName = eventName;
          if (eventName === "i18n_full") {
            this.applyI18n(data as I18nPayload);
            return;
          }
          if (eventName === "backend_full" || typeof data === "object") {
            this.backendPayload = data as any;
          }
        },
      });
    },
    applyI18n(payload: I18nPayload) {
      this.i18nLocale = payload.locale;
      applyI18nPayload(payload);
    },
    clearFeedback() {
      if (feedbackTimer) {
        clearTimeout(feedbackTimer);
        feedbackTimer = null;
      }
      this.feedback = null;
    },
    scheduleFeedbackClear() {
      if (feedbackTimer) {
        clearTimeout(feedbackTimer);
      }
      feedbackTimer = setTimeout(() => {
        this.feedback = null;
        feedbackTimer = null;
      }, 2800);
    },
    async runAction(
      endpoint: string,
      fields: Record<string, string | number | boolean | null | undefined> = {},
    ) {
      this.actionBusy = true;
      try {
        this.feedback = await postBackendAction(endpoint, fields);
        this.scheduleFeedbackClear();
        return this.feedback;
      } catch (error) {
        this.feedback = {
          ok: false,
          level: "error",
          message: error instanceof Error ? error.message : String(error),
        };
        this.scheduleFeedbackClear();
        return this.feedback;
      } finally {
        this.actionBusy = false;
      }
    },
  },
});
