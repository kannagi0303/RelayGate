<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import { useBackendStore } from "@/stores/backend";
import MarkdownDoc from "@/components/MarkdownDoc.vue";

const backend = useBackendStore();
const { t } = useI18n();
const payload = computed(() => backend.userScript ?? { items: [] });
const summary = computed(() => {
  const items = payload.value.items ?? [];
  const enabled = items.filter((item: any) => item.enabled).length;
  return { enabled, total: items.length };
});
const helpMarkdown = computed(() => String(t("user_script_page.help.markdown")));

function openFolder() {
  void backend.runAction("/backend/actions/user-script/open-folder");
}

function toggle(item: any) {
  void backend.runAction("/backend/actions/user-script/toggle", {
    id: String(item.filename ?? ""),
    enabled: item.enabled ? "false" : "true",
  });
}
</script>

<template>
  <section class="page-stack">
    <header class="page-header">
      <p class="eyebrow">{{ t("nav.extensions") }}</p>
      <h1>{{ t("user_script_page.title") }}</h1>
      <p class="page-copy">{{ t("user_script_page.sub") }}</p>
    </header>

    <div class="surface summary-panel">
      <div class="summary-list route-summary-list">
        <div class="summary-item">
          <span>{{ t("user_script_page.summary.scripts") }}</span>
          <strong>{{ summary.enabled }} / {{ summary.total }}</strong>
          <small>{{ t("dns.status.enabled_total") }}</small>
        </div>
      </div>
    </div>

    <div class="surface table-surface">
      <div class="table-heading">
        <div>
          <h2>{{ t("user_script_page.list") }}</h2>
        </div>
      </div>
      <div class="table-inline-form upstream-add-form">
        <button type="button" class="btn secondary" @click="openFolder">
          {{ t("user_script_page.open_folder") }}
        </button>
      </div>
      <table>
        <thead>
          <tr>
            <th>{{ t("common.status") }}</th>
            <th>{{ t("user_script_page.script_name") }}</th>
            <th>{{ t("user_script_page.comment") }}</th>
            <th>{{ t("common.action") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!payload.items?.length">
            <td colspan="4">{{ t("common.none") }}</td>
          </tr>
          <tr v-for="item in payload.items" :key="item.filename">
            <td class="status-cell">
              <span class="status-pill" :class="item.status">{{ item.status_label }}</span>
            </td>
            <td>
              <strong>{{ item.name || item.filename }}</strong>
              <div class="cell-note mono">{{ item.filename }}</div>
            </td>
            <td>
              <span>{{ item.comment || t("common.none") }}</span>
            </td>
            <td>
              <button
                v-if="item.operable"
                type="button"
                class="btn table-btn"
                :class="{ secondary: item.enabled }"
                @click="toggle(item)"
              >
                {{ item.enabled ? t("common.disable") : t("common.enable") }}
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
      <p class="path-line mono">{{ payload.script_dir }}</p>
    </div>
  </section>
</template>
