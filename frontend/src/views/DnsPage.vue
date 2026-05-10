<script setup lang="ts">
import { computed, reactive } from "vue";
import { useI18n } from "vue-i18n";
import { useBackendStore } from "@/stores/backend";
import MarkdownDoc from "@/components/MarkdownDoc.vue";
import { dnsProviderName } from "@/lib/dnsProviders";

const backend = useBackendStore();
const { t } = useI18n();
const payload = computed(() => backend.dns ?? { profiles: [], routes: [], profile_options: [] });
const profileForm = reactive({ server_ip: "", server_port: "53" });
const routeForm = reactive({ host_pattern: "", profile_id: "" });
const helpMarkdown = computed(() => String(t("dns.help.markdown")));
const profileSummary = computed(() => {
  const profiles = payload.value.profiles ?? [];
  const enabled = profiles.filter((item: any) => item.enabled).length;
  return { enabled, total: profiles.length };
});
const routeSummary = computed(() => {
  const routes = payload.value.routes ?? [];
  const enabled = routes.filter((item: any) => item.enabled).length;
  return { enabled, total: routes.length };
});
const profileIds = computed(() => (payload.value.profiles ?? []).map((item: any) => String(item.id)));
const profilesById = computed(() =>
  new Map((payload.value.profiles ?? []).map((item: any) => [String(item.id), item])),
);

async function addProfile() {
  const result = await backend.runAction("/backend/actions/dns-profiles/add", profileForm);
  if (result.ok) {
    profileForm.server_ip = "";
    profileForm.server_port = "53";
  }
}

async function addRoute() {
  const result = await backend.runAction("/backend/actions/dns-routes/add", {
    host_pattern: routeForm.host_pattern,
    profile_id: routeForm.profile_id || payload.value.profile_options?.[0] || "",
  });
  if (result.ok) routeForm.host_pattern = "";
}

function toggleProfile(item: any) {
  void backend.runAction("/backend/actions/dns-profiles/toggle", {
    id: item.id,
    enabled: item.enabled ? "false" : "true",
  });
}

function toggleRoute(item: any) {
  void backend.runAction("/backend/actions/dns-routes/toggle", {
    id: item.id,
    enabled: item.enabled ? "false" : "true",
  });
}

function moveProfile(item: any, direction: "up" | "down") {
  void backend.runAction("/backend/actions/dns-profiles/move", {
    id: item.id,
    direction,
  });
}

function firstServer(item: any) {
  return String(item.servers?.[0] ?? "");
}

function serverIp(item: any) {
  const server = firstServer(item);
  if (!server) return t("common.none");
  if (server.startsWith("[")) {
    return server.slice(1, server.indexOf("]"));
  }
  return server.split(":")[0] || t("common.none");
}

function serverPort(item: any) {
  const server = firstServer(item);
  if (!server) return t("common.none");
  if (server.startsWith("[")) {
    const port = server.slice(server.indexOf("]") + 2);
    return port || "53";
  }
  return server.split(":")[1] || "53";
}

function serviceName(item: any) {
  const ip = serverIp(item);
  if (!ip || ip === t("common.none")) return "";
  return dnsProviderName(ip);
}

function profileDisplayLabel(item: any) {
  const ip = serverIp(item);
  const name = serviceName(item);
  if (name && ip && ip !== t("common.none")) return `${name} (${ip})`;
  if (ip && ip !== t("common.none")) return ip;
  return t("common.none");
}

function routeProfileLabel(profileId: string) {
  const profile = profilesById.value.get(String(profileId));
  if (!profile) return t("dns.routes.missing_profile");
  return profileDisplayLabel(profile);
}

function canMoveProfile(item: any, direction: "up" | "down") {
  const index = profileIds.value.indexOf(String(item.id));
  if (index < 0) return false;
  if (direction === "up") return index > 0;
  return index < profileIds.value.length - 1;
}
</script>

<template>
  <section class="page-stack">
    <header class="page-header">
      <p class="eyebrow">{{ t("nav.connection_routing") }}</p>
      <h1>{{ t("dns.title") }}</h1>
      <p class="page-copy">{{ t("dns.subtitle") }}</p>
    </header>

    <div class="surface summary-panel">
      <div class="summary-list dns-summary-list">
        <div class="summary-item">
          <span>{{ t("dns.status.runtime") }}</span>
          <strong>{{ payload.enabled ? t("common.enabled") : t("common.disabled") }}</strong>
        </div>
        <div class="summary-item">
          <span>{{ t("dns.status.profiles") }}</span>
          <strong>{{ profileSummary.enabled }} / {{ profileSummary.total }}</strong>
          <small>{{ t("dns.status.enabled_total") }}</small>
        </div>
        <div class="summary-item">
          <span>{{ t("dns.status.routes") }}</span>
          <strong>{{ routeSummary.enabled }} / {{ routeSummary.total }}</strong>
          <small>{{ t("dns.status.enabled_total") }}</small>
        </div>
      </div>
    </div>

    <div class="surface table-surface">
      <div class="table-heading">
        <div>
          <h2>{{ t("dns.tables.profiles") }}</h2>
        </div>
      </div>
      <form class="table-inline-form profile-add-form" @submit.prevent="addProfile">
        <label>
          <span>{{ t("dns.fields.ip") }}</span>
          <input
            v-model="profileForm.server_ip"
            type="text"
            :placeholder="t('dns.placeholders.ip')"
          />
        </label>
        <label>
          <span>{{ t("dns.fields.port") }}</span>
          <input v-model="profileForm.server_port" type="text" placeholder="53" />
        </label>
        <button type="submit" class="btn">{{ t("dns.actions.add_profile") }}</button>
      </form>
      <table>
        <thead>
          <tr>
            <th>{{ t("dns.cols.service") }}</th>
            <th>{{ t("dns.cols.ip") }}</th>
            <th>{{ t("dns.cols.port") }}</th>
            <th>{{ t("dns.cols.status") }}</th>
            <th>{{ t("dns.cols.action") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!payload.profiles?.length">
            <td colspan="5">{{ t("dns.empty.profiles") }}</td>
          </tr>
          <tr v-for="item in payload.profiles" :key="item.id">
            <td>{{ serviceName(item) }}</td>
            <td class="mono">{{ serverIp(item) }}</td>
            <td class="mono">{{ serverPort(item) }}</td>
            <td>{{ item.enabled ? t("common.enabled") : t("common.disabled") }}</td>
            <td class="actions compact">
              <button
                type="button"
                class="btn table-btn secondary"
                :disabled="!canMoveProfile(item, 'up')"
                @click="moveProfile(item, 'up')"
              >
                {{ t("common.move_up") }}
              </button>
              <button
                type="button"
                class="btn table-btn secondary"
                :disabled="!canMoveProfile(item, 'down')"
                @click="moveProfile(item, 'down')"
              >
                {{ t("common.move_down") }}
              </button>
              <button type="button" class="btn table-btn secondary" @click="toggleProfile(item)">
                {{ item.enabled ? t("common.disable") : t("common.enable") }}
              </button>
              <button type="button" class="btn table-btn danger" @click="backend.runAction('/backend/actions/dns-profiles/delete', { id: item.id })">
                {{ t("common.delete") }}
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="surface table-surface">
      <div class="table-heading">
        <div>
          <h2>{{ t("dns.tables.routes") }}</h2>
        </div>
      </div>
      <form class="table-inline-form route-add-form" @submit.prevent="addRoute">
        <label>
          <span>{{ t("dns.fields.pattern") }}</span>
          <input
            v-model="routeForm.host_pattern"
            type="text"
            placeholder="*.example.com"
          />
        </label>
        <label>
          <span>{{ t("dns.fields.service") }}</span>
          <select v-model="routeForm.profile_id">
            <option v-for="id in payload.profile_options" :key="id" :value="id">
              {{ routeProfileLabel(id) }}
            </option>
          </select>
        </label>
        <button type="submit" class="btn">{{ t("dns.actions.add_route") }}</button>
      </form>
      <table>
        <thead>
          <tr>
            <th>{{ t("dns.cols.pattern") }}</th>
            <th>{{ t("dns.cols.service") }}</th>
            <th>{{ t("dns.cols.status") }}</th>
            <th>{{ t("dns.cols.action") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!payload.routes?.length">
            <td colspan="4">{{ t("dns.empty.routes") }}</td>
          </tr>
          <tr v-for="item in payload.routes" :key="item.id">
            <td class="mono">{{ item.host_pattern }}</td>
            <td>{{ routeProfileLabel(item.profile_id) }}</td>
            <td>{{ item.enabled ? t("common.enabled") : t("common.disabled") }}</td>
            <td class="actions compact">
              <button type="button" class="btn table-btn secondary" @click="toggleRoute(item)">
                {{ item.enabled ? t("common.disable") : t("common.enable") }}
              </button>
              <button type="button" class="btn table-btn danger" @click="backend.runAction('/backend/actions/dns-routes/delete', { id: item.id })">
                {{ t("common.delete") }}
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="surface action-panel">
      <div class="table-heading">
        <div>
          <h2>{{ t("dns.help.title") }}</h2>
        </div>
      </div>
      <MarkdownDoc :source="helpMarkdown" />
    </div>
  </section>
</template>
