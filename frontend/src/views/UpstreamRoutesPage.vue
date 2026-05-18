<script setup lang="ts">
import { computed, reactive } from "vue";
import { useI18n } from "vue-i18n";
import { useBackendStore } from "@/stores/backend";
import MarkdownDoc from "@/components/MarkdownDoc.vue";

const backend = useBackendStore();
const { t } = useI18n();
const payload = computed(() => backend.upstreamRoutes ?? { items: [], upstream_options: [] });
const form = reactive({ host_pattern: "", upstream_id: "" });
const upstreams = computed(() => backend.upstreams?.items ?? []);
const upstreamsById = computed(() =>
  new Map<string, any>(upstreams.value.map((item: any) => [String(item.id), item])),
);
const summary = computed(() => {
  const items = payload.value.items ?? [];
  const enabled = items.filter((item: any) => item.enabled).length;
  return { enabled, total: items.length };
});
const helpMarkdown = computed(() => String(t("upstream_routes_page.help.markdown")));

async function add() {
  const upstreamId = form.upstream_id || payload.value.upstream_options?.[0] || "";
  const result = await backend.runAction("/backend/actions/upstream-routes/add", {
    host_pattern: form.host_pattern,
    upstream_id: upstreamId,
  });
  if (result.ok) form.host_pattern = "";
}

function toggle(item: any) {
  void backend.runAction("/backend/actions/upstream-routes/toggle", {
    id: item.id,
    enabled: item.enabled ? "false" : "true",
  });
}

function remove(item: any) {
  void backend.runAction("/backend/actions/upstream-routes/delete", { id: item.id });
}

function upstreamLabel(id: string) {
  const upstream = upstreamsById.value.get(String(id));
  if (!upstream) return t("upstream_routes_page.missing_upstream");
  return String(upstream.address ?? id);
}
</script>

<template>
  <section class="page-stack">
    <header class="page-header">
      <p class="eyebrow">{{ t("nav.connection_routing") }}</p>
      <h1>{{ t("upstream_routes_page.title") }}</h1>
      <p class="page-copy">{{ t("upstream_routes_page.sub") }}</p>
    </header>

    <div class="surface summary-panel">
      <div class="summary-list route-summary-list">
        <div class="summary-item">
          <span>{{ t("upstream_routes_page.summary.routes") }}</span>
          <strong>{{ summary.enabled }} / {{ summary.total }}</strong>
          <small>{{ t("dns.status.enabled_total") }}</small>
        </div>
      </div>
    </div>

    <div class="surface table-surface">
      <div class="table-heading">
        <div>
          <h2>{{ t("upstream_routes_page.list") }}</h2>
        </div>
      </div>
      <form class="table-inline-form route-add-form" @submit.prevent="add">
        <label>
          <span>{{ t("upstream_routes_page.pattern") }}</span>
          <input v-model="form.host_pattern" type="text" placeholder="*.example.com" />
        </label>
        <label>
          <span>{{ t("upstream_routes_page.upstream") }}</span>
          <select v-model="form.upstream_id">
            <option v-for="id in payload.upstream_options" :key="id" :value="id">
              {{ upstreamLabel(id) }}
            </option>
          </select>
        </label>
        <button type="submit" class="btn">{{ t("upstream_routes_page.add") }}</button>
      </form>
      <table>
        <thead>
          <tr>
            <th>{{ t("upstream_routes_page.pattern") }}</th>
            <th>{{ t("upstream_routes_page.upstream") }}</th>
            <th>{{ t("common.status") }}</th>
            <th>{{ t("common.action") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!payload.items?.length">
            <td colspan="4">{{ t("upstream_routes_page.none") }}</td>
          </tr>
          <tr v-for="item in payload.items" :key="item.id">
            <td class="mono">{{ item.host_pattern }}</td>
            <td class="mono">{{ upstreamLabel(item.upstream_id) }}</td>
            <td>{{ item.enabled ? t("common.enabled") : t("common.disabled") }}</td>
            <td class="actions compact">
              <button type="button" class="btn table-btn secondary" @click="toggle(item)">
                {{ item.enabled ? t("common.disable") : t("common.enable") }}
              </button>
              <button type="button" class="btn table-btn danger" @click="remove(item)">
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
