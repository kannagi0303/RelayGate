<script setup lang="ts">
import { computed, reactive } from "vue";
import { useI18n } from "vue-i18n";
import { useBackendStore } from "@/stores/backend";
import MarkdownDoc from "@/components/MarkdownDoc.vue";
import { dnsProviderName } from "@/lib/dnsProviders";

const backend = useBackendStore();
const { t } = useI18n();
const hasDnsPayload = computed(() => backend.dns !== null);
const payload = computed(() => backend.dns ?? { profiles: [], routes: [], profile_options: [] });
const profileForm = reactive({ server_ip: "", server_port: "53" });
const routeForm = reactive({ host_pattern: "", profile_id: "" });
const helpMarkdown = computed(() => String(t("dns.help.markdown")));
const customProfiles = computed(() => (payload.value.profiles ?? []).filter((item: any) => !item.is_system));
const routeProfileOptions = computed(() =>
  (payload.value.profiles ?? []).filter((item: any) => item.enabled && !item.is_system && firstServer(item)),
);
const serverSummary = computed(() => {
  const servers = customProfiles.value;
  const enabled = servers.filter((item: any) => item.enabled).length;
  return { enabled, total: servers.length };
});

async function addProfile() {
  const result = await backend.runAction("/backend/actions/dns-profiles/add", profileForm);
  if (result.ok) {
    profileForm.server_ip = "";
    profileForm.server_port = "53";
  }
}

async function addRoute() {
  if (!routeForm.profile_id && routeProfileOptions.value.length) {
    routeForm.profile_id = String(routeProfileOptions.value[0].id);
  }
  const result = await backend.runAction("/backend/actions/dns-routes/add", {
    host_pattern: routeForm.host_pattern,
    profile_id: routeForm.profile_id,
  });
  if (result.ok) {
    routeForm.host_pattern = "";
  }
}

function firstServer(item: any) {
  return String(item.servers?.[0] ?? "");
}

function serverIp(item: any) {
  if (item.is_system) return t("common.auto");
  const server = firstServer(item);
  if (!server) return t("common.none");
  if (server.startsWith("[")) {
    return server.slice(1, server.indexOf("]"));
  }
  return server.split(":")[0] || t("common.none");
}

function serverPort(item: any) {
  if (item.is_system) return t("common.auto");
  const server = firstServer(item);
  if (!server) return t("common.none");
  if (server.startsWith("[")) {
    const port = server.slice(server.indexOf("]") + 2);
    return port || "53";
  }
  return server.split(":")[1] || "53";
}

function serviceName(item: any) {
  if (item.is_system) return "System";
  const ip = serverIp(item);
  if (!ip || ip === t("common.none")) return "";
  return dnsProviderName(ip);
}

function endpointLabel(item: any) {
  const ip = serverIp(item);
  if (!ip || ip === t("common.none")) return t("common.none");
  if (item.is_system) return t("common.auto");
  return `${ip}:${serverPort(item)}`;
}

function showSingleLineService(item: any) {
  return !serviceName(item) && !item.is_system;
}

function percent(value: unknown) {
  const number = Number(value);
  if (!Number.isFinite(number)) return t("common.none");
  return `${Math.round(number * 100)}%`;
}

function milliseconds(value: unknown) {
  const number = Number(value);
  if (!Number.isFinite(number)) return t("common.none");
  return `${Math.round(number)} ms`;
}

function dnsRuntimeStatus() {
  if (!hasDnsPayload.value) return t("common.loading");
  return payload.value.enabled ? t("common.enabled") : t("common.disabled");
}

function profileById(id: string) {
  return (payload.value.profiles ?? []).find((item: any) => item.id === id);
}

function dnsRouteTargetLabel(item: any) {
  const endpoint = endpointLabel(item);
  if (!endpoint || endpoint === t("common.none") || item.is_system) return endpoint;
  const provider = serviceName(item);
  return provider ? `${endpoint} (${provider})` : endpoint;
}

function routeProfileLabel(id: string) {
  const profile = profileById(id);
  if (!profile || profile.is_system) return id || t("common.none");
  return dnsRouteTargetLabel(profile);
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
          <strong>{{ dnsRuntimeStatus() }}</strong>
        </div>
        <div class="summary-item">
          <span>{{ t("dns.status.servers") }}</span>
          <strong>{{ serverSummary.enabled }} / {{ serverSummary.total }}</strong>
          <small>{{ t("dns.status.enabled_total") }}</small>
        </div>
        <div class="summary-item">
          <span>{{ t("dns.status.cache") }}</span>
          <strong>{{ hasDnsPayload ? payload.cache_entries : t("common.loading") }}</strong>
          <small>{{ t("status_page.entries") }}</small>
        </div>
      </div>
    </div>

    <div class="surface table-surface">
      <div class="table-heading">
        <div>
          <h2>{{ t("dns.tables.servers") }}</h2>
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
        <button type="submit" class="btn">{{ t("dns.actions.add_server") }}</button>
      </form>
      <table>
        <thead>
          <tr>
            <th>{{ t("dns.cols.service") }}</th>
            <th>{{ t("dns.cols.latency") }}</th>
            <th>{{ t("dns.cols.score") }}</th>
            <th>{{ t("dns.cols.success") }}</th>
            <th>{{ t("dns.cols.action") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!payload.profiles?.length">
            <td colspan="5">{{ t("dns.empty.servers") }}</td>
          </tr>
          <tr v-for="item in payload.profiles" :key="item.id" :class="{ 'dns-active-row': item.is_active }">
            <td>
              <div class="dns-service-cell" :class="{ 'is-active': item.is_active, 'single-line': showSingleLineService(item) }">
                <template v-if="item.is_system">
                  <span class="dns-service-title">System</span>
                  <span class="dns-service-meta">{{ t("common.auto") }}</span>
                </template>
                <template v-else-if="showSingleLineService(item)">
                  <span class="dns-service-title mono">{{ endpointLabel(item) }}</span>
                </template>
                <template v-else>
                  <span class="dns-service-title">{{ serviceName(item) }}</span>
                  <span class="dns-service-meta mono">{{ endpointLabel(item) }}</span>
                </template>
              </div>
            </td>
            <td>{{ milliseconds(item.average_latency_ms) }}</td>
            <td>{{ item.health_score ?? t("common.none") }}</td>
            <td>{{ percent(item.success_rate) }}</td>
            <td class="actions compact">
              <button v-if="!item.is_system" type="button" class="btn table-btn danger" @click="backend.runAction('/backend/actions/dns-profiles/delete', { id: item.id })">
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
      <form class="table-inline-form dns-route-add-form" @submit.prevent="addRoute">
        <label>
          <span>{{ t("dns.fields.pattern") }}</span>
          <input
            v-model="routeForm.host_pattern"
            type="text"
            :placeholder="t('dns.placeholders.pattern')"
          />
        </label>
        <label>
          <span>{{ t("dns.cols.profile") }}</span>
          <select v-model="routeForm.profile_id">
            <option value="" disabled>{{ t("dns.placeholders.profile") }}</option>
            <option v-for="item in routeProfileOptions" :key="item.id" :value="item.id">
              {{ routeProfileLabel(item.id) }}
            </option>
          </select>
        </label>
        <button type="submit" class="btn">{{ t("dns.actions.add_route") }}</button>
      </form>
      <table>
        <thead>
          <tr>
            <th>{{ t("dns.cols.pattern") }}</th>
            <th>{{ t("dns.cols.profile") }}</th>
            <th>{{ t("dns.cols.action") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!payload.routes?.length">
            <td colspan="3">{{ t("dns.empty.routes") }}</td>
          </tr>
          <tr v-for="item in payload.routes" :key="item.id">
            <td class="mono">{{ item.host_pattern }}</td>
            <td>
              <span :class="{ muted: !item.profile_exists }">{{ routeProfileLabel(item.profile_id) }}</span>
              <small v-if="!item.profile_exists" class="field-hint warning">{{ t("dns.routes.missing_profile") }}</small>
            </td>
            <td class="actions compact">
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


<style scoped>
.dns-service-cell {
  display: grid;
  gap: calc(2 / 16 * 1rem);
}

.dns-service-cell.single-line {
  display: block;
}

.dns-service-title {
  color: var(--rg-ink);
  font-weight: 700;
  line-height: 1.35;
}

.dns-service-meta {
  color: var(--rg-muted);
  font-size: calc(13 / 16 * 1rem);
  line-height: 1.35;
}

.dns-service-cell.is-active .dns-service-title,
.dns-service-cell.is-active .dns-service-meta {
  color: var(--rg-accent-strong);
}

.dns-route-add-form {
  grid-template-columns: minmax(0, 1.35fr) minmax(calc(220 / 16 * 1rem), 1fr) auto;
}

.checkbox-inline {
  align-self: center;
  display: flex;
  align-items: center;
  gap: calc(8 / 16 * 1rem);
  padding-bottom: calc(4 / 16 * 1rem);
}

.checkbox-inline input {
  margin: 0;
}

.muted {
  color: var(--rg-muted);
}

.field-hint.warning {
  display: block;
  color: var(--rg-danger);
}
</style>
