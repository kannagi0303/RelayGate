<script setup lang="ts">
import { computed, reactive } from "vue";
import { useI18n } from "vue-i18n";
import { useBackendStore } from "@/stores/backend";
import MarkdownDoc from "@/components/MarkdownDoc.vue";

const backend = useBackendStore();
const { t } = useI18n();
const payload = computed(() => backend.upstreams ?? { items: [] });
const form = reactive({ address: "" });
const summary = computed(() => {
  const items = payload.value.items ?? [];
  const enabled = items.filter((item: any) => item.enabled).length;
  return { enabled, total: items.length };
});
const helpMarkdown = computed(() => String(t("upstreams_page.help.markdown")));

async function add() {
  const result = await backend.runAction("/backend/actions/upstreams/add", form);
  if (result.ok) form.address = "";
}

function toggle(item: any) {
  void backend.runAction("/backend/actions/upstreams/toggle", {
    id: item.id,
    enabled: item.enabled ? "false" : "true",
  });
}

function remove(item: any) {
  void backend.runAction("/backend/actions/upstreams/delete", { id: item.id });
}
</script>

<template>
  <section class="page-stack">
    <header class="page-header">
      <p class="eyebrow">{{ t("nav.connection_routing") }}</p>
      <h1>{{ t("upstreams_page.title") }}</h1>
      <p class="page-copy">{{ t("upstreams_page.sub") }}</p>
    </header>

    <div class="surface summary-panel">
      <div class="summary-list route-summary-list">
        <div class="summary-item">
          <span>{{ t("upstreams_page.summary.upstreams") }}</span>
          <strong>{{ summary.enabled }} / {{ summary.total }}</strong>
          <small>{{ t("dns.status.enabled_total") }}</small>
        </div>
      </div>
    </div>

    <div class="surface table-surface">
      <div class="table-heading">
        <div>
          <h2>{{ t("upstreams_page.list") }}</h2>
        </div>
      </div>
      <form class="table-inline-form upstream-add-form" @submit.prevent="add">
        <label>
          <span>{{ t("upstreams_page.address") }}</span>
          <input v-model="form.address" type="text" placeholder="http://127.0.0.1:7890" />
        </label>
        <button type="submit" class="btn">{{ t("upstreams_page.add") }}</button>
      </form>
      <table>
        <thead>
          <tr>
            <th>{{ t("upstreams_page.address") }}</th>
            <th>{{ t("common.status") }}</th>
            <th>{{ t("common.action") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!payload.items?.length">
            <td colspan="3">{{ t("upstreams_page.none") }}</td>
          </tr>
          <tr v-for="item in payload.items" :key="item.id">
            <td class="mono">{{ item.address }}</td>
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
