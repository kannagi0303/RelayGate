<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted } from "vue";
import { useI18n } from "vue-i18n";
import { dnsProviderName } from "@/lib/dnsProviders";
import { useBackendStore } from "@/stores/backend";

const backend = useBackendStore();
const { t } = useI18n();
const payload = computed(() => backend.connectionInfo ?? { max_items: 0, items: [] });
const dnsProfiles = computed(() => {
  const map = new Map<string, any>();
  for (const profile of backend.dns?.profiles ?? []) {
    if (profile?.id) map.set(profile.id, profile);
  }
  return map;
});
let refreshTimer: ReturnType<typeof setInterval> | null = null;

onMounted(() => {
  void backend.refreshConnectionInfo();
  refreshTimer = setInterval(() => {
    void backend.refreshConnectionInfo();
  }, 2000);
});

onBeforeUnmount(() => {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
});

function parseDnsServer(server: string): { ip: string; port?: string } {
  const bracket = server.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (bracket) return { ip: bracket[1], port: bracket[2] };

  const colonCount = (server.match(/:/g) ?? []).length;
  if (colonCount === 1) {
    const [ip, port] = server.split(":");
    return { ip, port };
  }

  return { ip: server };
}

function formatDnsServer(server: string) {
  const { ip, port } = parseDnsServer(server);
  const provider = dnsProviderName(ip);
  const portText = port && port !== "53" ? `:${port}` : "";
  return provider ? `${ip}${portText} (${provider})` : `${ip}${portText}`;
}

function formatDns(item: any) {
  const profileId = item.dns_profile;
  if (!profileId) return t("connection_info_page.upstream_dns_unknown");
  if (profileId === "system") return t("connection_info_page.system_dns");

  const profile = dnsProfiles.value.get(profileId);
  const servers = Array.isArray(profile?.servers) ? profile.servers : [];
  if (servers.length > 0) {
    const first = formatDnsServer(String(servers[0]));
    return servers.length > 1 ? `${first} +${servers.length - 1}` : first;
  }

  return profileId;
}

function formatFamily(item: any) {
  const family = item.last_family || "-";
  const ip = item.last_ip ? ` ${item.last_ip}` : "";
  const elapsed = item.last_connect_ms != null ? ` ${item.last_connect_ms}ms` : "";
  return `${family}${ip}${elapsed}`;
}

function formatPreference(value: string) {
  if (value === "prefer_ipv4") return t("connection_info_page.prefer_ipv4");
  if (value === "prefer_ipv6") return t("connection_info_page.prefer_ipv6");
  return t("connection_info_page.prefer_neutral");
}
</script>

<template>
  <section class="page-stack">
    <header class="page-header">
      <p class="eyebrow">{{ t("nav.connection_routing") }}</p>
      <h1>{{ t("connection_info_page.title") }}</h1>
      <p class="page-copy">{{ t("connection_info_page.sub") }}</p>
    </header>

    <div class="surface summary-panel">
      <div class="summary-list dns-summary-list">
        <div class="summary-item"><span>{{ t("connection_info_page.recent_hosts") }}</span><strong>{{ payload.items?.length ?? 0 }}</strong></div>
        <div class="summary-item"><span>{{ t("connection_info_page.max_items") }}</span><strong>{{ payload.max_items ?? 0 }}</strong></div>
        <div class="summary-item"><span>{{ t("connection_info_page.refresh") }}</span><strong>2s</strong></div>
      </div>
    </div>

    <div class="surface table-surface connection-info-table">
      <div class="table-heading">
        <div>
          <h2>{{ t("connection_info_page.host_table") }}</h2>
        </div>
      </div>
      <table>
        <thead>
          <tr>
            <th>{{ t("common.host") }}</th>
            <th>{{ t("connection_info_page.dns") }}</th>
            <th>{{ t("connection_info_page.actual_family") }}</th>
            <th>{{ t("connection_info_page.preference") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!payload.items?.length">
            <td colspan="4">{{ t("connection_info_page.none") }}</td>
          </tr>
          <tr v-for="item in payload.items" :key="item.host">
            <td class="mono">{{ item.host }}</td>
            <td class="mono">{{ formatDns(item) }}</td>
            <td class="mono">{{ formatFamily(item) }}</td>
            <td>{{ formatPreference(item.family_preference) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>
