<script setup lang="ts">
import { computed, reactive } from "vue";
import { useI18n } from "vue-i18n";
import { useBackendStore } from "@/stores/backend";
import MarkdownDoc from "@/components/MarkdownDoc.vue";

const backend = useBackendStore();
const { t } = useI18n();
const payload = computed(() => backend.gateway ?? { items: [], upstream_options: [] });
const upstreams = computed(() => backend.upstreams?.items ?? []);
const upstreamsById = computed(() =>
  new Map<string, any>(upstreams.value.map((item: any) => [String(item.id), item])),
);
const form = reactive({
  mount_path: "",
  target_base_url: "",
  upstream_id: "",
  rewrite_links: true,
});
const summary = computed(() => {
  const items = payload.value.items ?? [];
  const enabled = items.filter((item: any) => item.enabled).length;
  return { enabled, total: items.length };
});
const helpMarkdown = computed(() => String(t("gateway_page.help.markdown")));

async function add() {
  const result = await backend.runAction("/backend/actions/gateway/add", {
    mount_path: form.mount_path,
    target_base_url: form.target_base_url,
    upstream_id: form.upstream_id,
    rewrite_links: form.rewrite_links ? "on" : "",
  });
  if (result.ok) {
    form.mount_path = "";
    form.target_base_url = "";
  }
}

function toggle(item: any) {
  void backend.runAction("/backend/actions/gateway/toggle", {
    id: item.id,
    enabled: item.enabled ? "false" : "true",
  });
}

function upstreamLabel(id: string | null | undefined) {
  if (!id) return t("common.none");
  const upstream = upstreamsById.value.get(String(id));
  if (!upstream) return t("gateway_page.missing_upstream");
  return String(upstream.address ?? id);
}
</script>

<template>
  <section class="page-stack">
    <header class="page-header">
      <p class="eyebrow">{{ t("nav.connection_routing") }}</p>
      <h1>{{ t("gateway_page.title") }}</h1>
      <p class="page-copy">{{ t("gateway_page.sub") }}</p>
    </header>

    <div class="surface summary-panel">
      <div class="summary-list route-summary-list">
        <div class="summary-item">
          <span>{{ t("gateway_page.summary.mounts") }}</span>
          <strong>{{ summary.enabled }} / {{ summary.total }}</strong>
          <small>{{ t("dns.status.enabled_total") }}</small>
        </div>
      </div>
    </div>

    <div class="surface table-surface">
      <div class="table-heading">
        <div>
          <h2>{{ t("gateway_page.list") }}</h2>
        </div>
      </div>
      <form class="table-inline-form gateway-add-form" @submit.prevent="add">
        <label>
          <span>{{ t("gateway_page.mount_path") }}</span>
          <input v-model="form.mount_path" type="text" placeholder="site" />
        </label>
        <label>
          <span>{{ t("gateway_page.target") }}</span>
          <input v-model="form.target_base_url" type="text" placeholder="https://example.com" />
        </label>
        <label>
          <span>{{ t("gateway_page.upstream") }}</span>
          <select v-model="form.upstream_id">
            <option value="">{{ t("common.none") }}</option>
            <option v-for="id in payload.upstream_options" :key="id" :value="id">
              {{ upstreamLabel(id) }}
            </option>
          </select>
        </label>
        <label class="check-row inline-check-row">
          <input v-model="form.rewrite_links" type="checkbox" role="switch" />
          <span>{{ t("gateway_page.rewrite_links") }}</span>
        </label>
        <button type="submit" class="btn">{{ t("gateway_page.add") }}</button>
      </form>
      <table>
        <thead>
          <tr>
            <th>{{ t("gateway_page.mount_path") }}</th>
            <th>{{ t("gateway_page.target") }}</th>
            <th>{{ t("gateway_page.upstream") }}</th>
            <th>{{ t("gateway_page.rewrite_links") }}</th>
            <th>{{ t("common.status") }}</th>
            <th>{{ t("common.action") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!payload.items?.length">
            <td colspan="6">{{ t("gateway_page.none") }}</td>
          </tr>
          <tr v-for="item in payload.items" :key="item.id">
            <td class="mono">{{ item.mount_path }}</td>
            <td class="mono">{{ item.target_base_url }}</td>
            <td class="mono">{{ upstreamLabel(item.upstream_id) }}</td>
            <td>{{ item.rewrite_links ? t("common.enabled") : t("common.disabled") }}</td>
            <td>{{ item.enabled ? t("common.enabled") : t("common.disabled") }}</td>
            <td class="actions compact">
              <button type="button" class="btn table-btn secondary" @click="toggle(item)">
                {{ item.enabled ? t("common.disable") : t("common.enable") }}
              </button>
              <button type="button" class="btn table-btn danger" @click="backend.runAction('/backend/actions/gateway/delete', { id: item.id })">
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
          <h2>{{ t("common.desc") }}</h2>
        </div>
      </div>
      <MarkdownDoc :source="helpMarkdown" />
    </div>
  </section>
</template>
