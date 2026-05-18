<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { useBackendStore } from "@/stores/backend";

const backend = useBackendStore();
const { t } = useI18n();
const status = computed(() => backend.status ?? {});
const settings = computed(() => backend.settings ?? {});
const dns = computed(() => backend.dns ?? { profiles: [], routes: [] });
const upstreams = computed(() => backend.upstreams ?? { items: [] });
const upstreamRoutes = computed(() => backend.upstreamRoutes ?? { items: [] });
const gateway = computed(() => backend.gateway ?? { items: [] });
const userScript = computed(() => backend.userScript ?? { items: [] });
const runtime = computed(() => status.value.runtime ?? {});
const processInfo = computed(() => status.value.process ?? {});

const nowMs = ref(Date.now());
const uptimeBaseSeconds = ref(0);
const uptimeBaseSyncedAt = ref(Date.now());
let uptimeTimer: ReturnType<typeof setInterval> | undefined;

const dash = (value: unknown) => {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
};

const formatUptime = (seconds: unknown) => {
  const total = Math.max(0, Math.floor(Number(seconds ?? 0)));
  if (!Number.isFinite(total) || total <= 0) {
    return "0s";
  }
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  const parts = [] as string[];
  if (days) parts.push(`${days}d`);
  if (hours || parts.length) parts.push(`${hours}h`);
  if (minutes || parts.length) parts.push(`${minutes}m`);
  parts.push(`${secs}s`);
  return parts.join(" ");
};

const formatBytes = (bytes: unknown) => {
  const value = Number(bytes);
  if (!Number.isFinite(value) || value <= 0) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
};

const hasFiniteNumber = (value: unknown) => Number.isFinite(Number(value));

const formatCpu = (value: unknown) => {
  const cpu = Number(value);
  if (!Number.isFinite(cpu)) return t("status_page.sampling");
  return `${cpu.toFixed(cpu < 10 ? 1 : 0)}%`;
};

const formatResourcePair = (cpu: unknown, memory: unknown) =>
  `${formatCpu(cpu)} / ${formatBytes(memory)}`;

function syncUptime(seconds: unknown) {
  const next = Number(seconds ?? 0);
  uptimeBaseSeconds.value = Number.isFinite(next) && next > 0 ? Math.floor(next) : 0;
  uptimeBaseSyncedAt.value = Date.now();
  nowMs.value = uptimeBaseSyncedAt.value;
}

watch(() => runtime.value.uptime_secs, syncUptime, { immediate: true });

onMounted(() => {
  uptimeTimer = setInterval(() => {
    nowMs.value = Date.now();
  }, 1000);
});

onBeforeUnmount(() => {
  if (uptimeTimer) {
    clearInterval(uptimeTimer);
  }
});

const dynamicUptimeSeconds = computed(() => {
  const elapsed = Math.floor((nowMs.value - uptimeBaseSyncedAt.value) / 1000);
  return uptimeBaseSeconds.value + Math.max(0, elapsed);
});

const dynamicUptimeText = computed(() => formatUptime(dynamicUptimeSeconds.value));

const listenParts = computed(() => {
  const listen = String(status.value.proxy_listen || settings.value.proxy_listen || "");
  const match = listen.match(/^\[?(.+?)\]?:(\d+)$/);
  if (!match) {
    const fallback = listen || t("common.none");
    return { host: fallback, port: t("common.none"), full: fallback };
  }
  return { host: match[1], port: match[2], full: `${match[1]}:${match[2]}` };
});

const resourcePrimary = computed(() => {
  if (hasFiniteNumber(processInfo.value.avg_cpu_percent_15m)) {
    return `${formatCpu(processInfo.value.avg_cpu_percent_15m)} · ${t("status_page.resource_avg_15m")}`;
  }
  return formatCpu(processInfo.value.cpu_percent);
});

const processSummary = computed(() => [
  {
    label: t("status_page.resource_now"),
    value: formatResourcePair(processInfo.value.cpu_percent, processInfo.value.memory_bytes),
  },
  {
    label: t("status_page.resource_avg_15m"),
    value: formatResourcePair(
      processInfo.value.avg_cpu_percent_15m,
      processInfo.value.avg_memory_bytes_15m,
    ),
  },
  {
    label: t("status_page.resource_peak_15m"),
    value: formatResourcePair(
      processInfo.value.peak_cpu_percent_15m,
      processInfo.value.peak_memory_bytes_15m,
    ),
  },
  {
    label: t("status_page.resource_session_peak"),
    value: formatResourcePair(
      processInfo.value.session_peak_cpu_percent,
      processInfo.value.session_peak_memory_bytes,
    ),
  },
  { label: "PID", value: dash(processInfo.value.pid) },
]);

const dnsProfiles = computed(() => dns.value.profiles ?? []);
const enabledDnsProfileCount = computed(
  () => dnsProfiles.value.filter((item: any) => item.enabled).length,
);
const enabledUpstreamCount = computed(
  () => (upstreams.value.items ?? []).filter((item: any) => item.enabled).length,
);
const enabledGatewayCount = computed(
  () => (gateway.value.items ?? []).filter((item: any) => item.enabled).length,
);
const enabledUserScriptCount = computed(
  () => (userScript.value.items ?? []).filter((item: any) => item.enabled).length,
);

const moduleSummary = computed(() => [
  {
    label: t("nav.adblock"),
    value: dash(status.value.adblock_rule_count),
    note: t("status_page.resource_count", { count: dash(status.value.adblock_resource_count) }),
  },
  {
    label: "Rewrite",
    value: dash(status.value.rewrite_rule_count),
    note: t("status_page.rules_loaded"),
  },
  {
    label: t("nav.resource_replace"),
    value: dash(status.value.resource_replace_rule_count),
    note: t("status_page.rules_loaded"),
  },
  {
    label: t("nav.user_script"),
    value: dash(enabledUserScriptCount.value),
    note: t("status_page.total_count", { count: dash(userScript.value.items?.length ?? 0) }),
  },
]);

const systemSummary = computed(() => [
  {
    label: "DNS Profiles",
    value: dash(enabledDnsProfileCount.value),
    note: t("status_page.total_count", { count: dash(dnsProfiles.value.length) }),
  },
  { label: "DNS Cache", value: dash(dns.value.cache_entries), note: t("status_page.entries") },
  {
    label: t("nav.upstreams"),
    value: dash(enabledUpstreamCount.value),
    note: t("status_page.total_count", { count: dash(upstreams.value.items?.length ?? 0) }),
  },
  {
    label: t("nav.gateway"),
    value: dash(enabledGatewayCount.value),
    note: t("status_page.total_count", { count: dash(gateway.value.items?.length ?? 0) }),
  },
]);
</script>

<template>
  <section class="page-stack dashboard-page">
    <header class="page-header">
      <p class="eyebrow">{{ t("status_page.dashboard") }}</p>
      <h1>{{ t("status_page.title") }}</h1>
      <p class="page-copy">{{ t("status_page.overview") }}</p>
    </header>

    <div class="stat-grid dashboard-stats">
      <div class="stat-card status-card-primary">
        <span>{{ t("status_page.runtime_state") }}</span>
        <strong>{{ t("status_page.running") }}</strong>
        <small>{{ t("status_page.frontend_state", { state: backend.connected ? t("app.online") : t("app.offline") }) }}</small>
      </div>
      <div class="stat-card">
        <span>{{ t("status_page.uptime") }}</span>
        <strong class="mono">{{ dynamicUptimeText }}</strong>
        <small>{{ t("status_page.uptime_note") }}</small>
      </div>
      <div class="stat-card">
        <span>{{ t("status_page.listen") }}</span>
        <strong class="mono">{{ listenParts.full }}</strong>
        <small>{{ t("status_page.https_auto") }}</small>
      </div>
      <div class="stat-card resource-card">
        <span>{{ t("status_page.resource_usage") }}</span>
        <strong class="mono">{{ resourcePrimary }}</strong>
        <small>
          <span v-for="item in processSummary" :key="item.label">
            {{ item.label }} {{ item.value }}
          </span>
        </small>
      </div>
    </div>

    <div class="dashboard-grid two-columns">
      <div class="surface summary-panel">
        <div class="section-heading compact-heading">
          <div>
            <p class="eyebrow">{{ t("status_page.baseline") }}</p>
            <h2>{{ t("status_page.module_summary") }}</h2>
          </div>
          <span class="pill">{{ t("status_page.loaded") }}</span>
        </div>
        <div class="summary-list">
          <div v-for="item in moduleSummary" :key="item.label" class="summary-item">
            <span>{{ item.label }}</span>
            <strong class="mono">{{ item.value }}</strong>
            <small>{{ item.note }}</small>
          </div>
        </div>
      </div>

      <div class="surface summary-panel">
        <div class="section-heading compact-heading">
          <div>
            <p class="eyebrow">{{ t("status_page.runtime") }}</p>
            <h2>{{ t("status_page.environment_summary") }}</h2>
          </div>
          <span class="pill">{{ t("status_page.passive") }}</span>
        </div>
        <div class="summary-list">
          <div v-for="item in systemSummary" :key="item.label" class="summary-item">
            <span>{{ item.label }}</span>
            <strong class="mono">{{ item.value }}</strong>
            <small>{{ item.note }}</small>
          </div>
        </div>
      </div>
    </div>

    <div class="surface table-surface dashboard-table">
      <div class="table-heading">
        <div>
          <p class="eyebrow">DNS</p>
          <h2>{{ t("status_page.dns_profile_summary") }}</h2>
        </div>
        <span class="pill">{{ dns.enabled ? t("common.enabled") : t("common.disabled") }}</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>{{ t("dns_page.profile") }}</th>
            <th>{{ t("dns_page.mode") }}</th>
            <th>{{ t("dns_page.servers") }}</th>
            <th>{{ t("common.status") }}</th>
            <th>{{ t("status_page.latency") }}</th>
            <th>{{ t("status_page.quality") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!dnsProfiles.length">
            <td colspan="6">{{ t("common.none") }}</td>
          </tr>
          <tr v-for="item in dnsProfiles" :key="item.id">
            <td class="mono">{{ item.id }}</td>
            <td>{{ item.mode }}</td>
            <td class="mono">{{ item.servers?.join(", ") || "system" }}</td>
            <td>{{ item.enabled ? t("common.enabled") : t("common.disabled") }}</td>
            <td class="mono">—</td>
            <td>{{ t("status_page.passive_stats_pending") }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="surface table-surface dashboard-table">
      <div class="table-heading">
        <div>
          <p class="eyebrow">Proxy</p>
          <h2>{{ t("status_page.upstream_summary") }}</h2>
        </div>
        <span class="pill">{{ t("status_page.enabled_count", { count: enabledUpstreamCount }) }}</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>{{ t("upstreams_page.address") }}</th>
            <th>{{ t("common.status") }}</th>
            <th>{{ t("status_page.routes") }}</th>
            <th>{{ t("status_page.quality") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!upstreams.items?.length">
            <td colspan="5">{{ t("common.none") }}</td>
          </tr>
          <tr v-for="item in upstreams.items" :key="item.id">
            <td class="mono">{{ item.id }}</td>
            <td class="mono">{{ item.address }}</td>
            <td>{{ item.enabled ? t("common.enabled") : t("common.disabled") }}</td>
            <td>{{ upstreamRoutes.items?.filter((route: any) => route.upstream_id === item.id).length ?? 0 }}</td>
            <td>{{ t("status_page.passive_stats_pending") }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="surface table-surface dashboard-table">
      <div class="table-heading">
        <div>
          <p class="eyebrow">{{ t("nav.gateway") }}</p>
          <h2>{{ t("status_page.gateway_summary") }}</h2>
        </div>
        <span class="pill">{{ t("status_page.mount_count", { count: gateway.items?.length ?? 0 }) }}</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>{{ t("nav.gateway") }}</th>
            <th>{{ t("gateway_page.target") }}</th>
            <th>{{ t("gateway_page.upstream") }}</th>
            <th>{{ t("common.status") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!gateway.items?.length">
            <td colspan="4">{{ t("common.none") }}</td>
          </tr>
          <tr v-for="item in gateway.items" :key="item.id">
            <td class="mono">{{ item.mount_path }}</td>
            <td class="mono">{{ item.target_base_url }}</td>
            <td class="mono">{{ item.upstream_id || t("common.none") }}</td>
            <td>{{ item.enabled ? t("common.enabled") : t("common.disabled") }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>
