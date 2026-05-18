import { defineStore } from "pinia";
import { connectBackendEvents } from "@/lib/backendEvents";
import { applyI18nPayload, type I18nPayload } from "@/plugins/i18n";
import { postBackendAction, type ActionFeedback } from "@/lib/actions";

export type BackendEnvelope =
  | { event: "backend_full"; payload: unknown }
  | { event: "i18n_full"; payload: I18nPayload }
  | { event: string; payload: unknown };

let feedbackTimer: ReturnType<typeof setTimeout> | null = null;
let initialSnapshotFallbackTimer: ReturnType<typeof setTimeout> | null = null;
let snapshotRequestId = 0;

function clearInitialSnapshotFallback() {
  if (initialSnapshotFallbackTimer) {
    clearTimeout(initialSnapshotFallbackTimer);
    initialSnapshotFallbackTimer = null;
  }
}

function mergeMitmStatus(existing: unknown, incoming: unknown): unknown {
  if (incoming === null || typeof incoming !== "object") return incoming;
  if (existing === null || typeof existing !== "object") return incoming;

  const existingMitm = existing as Record<string, unknown>;
  const incomingMitm = incoming as Record<string, unknown>;
  const merged = { ...existingMitm, ...incomingMitm };

  const incomingHasOnlyFastTrust =
    incomingMitm.windows_user_root_trusted == null &&
    Array.isArray(incomingMitm.windows_relaygate_cas) &&
    incomingMitm.windows_relaygate_cas.length === 0;

  if (incomingHasOnlyFastTrust) {
    if (existingMitm.windows_user_root_trusted != null) {
      merged.windows_user_root_trusted = existingMitm.windows_user_root_trusted;
    }
    if (Array.isArray(existingMitm.windows_relaygate_cas)) {
      merged.windows_relaygate_cas = existingMitm.windows_relaygate_cas;
    }
  }

  return merged;
}

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
    connectionInfo: (state) => state.backendPayload?.connection_info ?? null,
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
          this.scheduleInitialSnapshotFallback();
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
          if (eventName === "backend_full") {
            clearInitialSnapshotFallback();
            this.applyBackendPayload(data);
            return;
          }
          if (data !== null && typeof data === "object") {
            this.applyBackendPayload(data);
          }
        },
      });
    },
    applyI18n(payload: I18nPayload) {
      this.i18nLocale = payload.locale;
      applyI18nPayload(payload);
    },
    applyBackendPayload(data: unknown) {
      if (data === null || typeof data !== "object") return;
      const incoming = { ...(data as Record<string, unknown>) };
      const processPayload = incoming.process;
      delete incoming.process;

      if (
        incoming.settings !== null &&
        typeof incoming.settings === "object" &&
        this.backendPayload?.settings !== null &&
        typeof this.backendPayload?.settings === "object"
      ) {
        const existingSettings = this.backendPayload.settings as Record<string, unknown>;
        const incomingSettings = incoming.settings as Record<string, unknown>;
        incoming.settings = {
          ...existingSettings,
          ...incomingSettings,
          mitm:
            "mitm" in incomingSettings
              ? mergeMitmStatus(existingSettings.mitm, incomingSettings.mitm)
              : existingSettings.mitm,
        };
      }

      let merged = this.backendPayload
        ? { ...this.backendPayload, ...incoming }
        : incoming;

      if (
        processPayload !== undefined &&
        merged.status !== null &&
        typeof merged.status === "object"
      ) {
        merged = {
          ...merged,
          status: {
            ...(merged.status as Record<string, unknown>),
            process: processPayload,
          },
        };
      }

      this.backendPayload = merged;
    },
    scheduleInitialSnapshotFallback() {
      clearInitialSnapshotFallback();
      if (this.backendPayload) return;
      initialSnapshotFallbackTimer = setTimeout(() => {
        initialSnapshotFallbackTimer = null;
        if (!this.backendPayload) {
          void this.refreshSnapshot();
        }
      }, 350);
    },
    async refreshSnapshot() {
      const requestId = ++snapshotRequestId;
      try {
        const response = await fetch("/backend/snapshot", {
          headers: { Accept: "application/json" },
          cache: "no-store",
        });
        if (!response.ok) return;
        const payload = await response.json();
        if (requestId !== snapshotRequestId) return;
        this.applyBackendPayload(payload);
      } catch {
        // SSE remains the primary live channel; snapshot refresh is best-effort.
      }
    },
    async refreshConnectionInfo() {
      try {
        const response = await fetch("/backend/connection-info", {
          headers: { Accept: "application/json" },
          cache: "no-store",
        });
        if (!response.ok) return;
        this.applyBackendPayload(await response.json());
      } catch {
        // Connection info is observational; stale UI is safer than retry pressure.
      }
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
