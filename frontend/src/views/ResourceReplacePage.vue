<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import { useBackendStore } from "@/stores/backend";
import MarkdownDoc from "@/components/MarkdownDoc.vue";

const backend = useBackendStore();
const { t } = useI18n();
const payload = computed(() => backend.resourceReplace ?? { rules: [] });
const helpMarkdown = computed(() => String(t("resource_replace_page.help.markdown")));

function toggle(item: any) {
  void backend.runAction("/backend/actions/resource-replace/toggle", {
    id: item.id,
    enabled: item.enabled ? "false" : "true",
  });
}
</script>

<template>
  <section class="page-stack">
    <header class="page-header">
      <p class="eyebrow">{{ t("nav.extensions") }}</p>
      <h1>{{ t("resource_replace_page.title") }}</h1>
      <p class="page-copy">{{ t("resource_replace_page.sub") }}</p>
    </header>

    <div class="surface summary-panel">
      <div class="summary-list route-summary-list">
        <div class="summary-item">
        <span>{{ t("resource_replace_page.rules") }}</span>
        <strong>{{ payload.enabled_rule_count ?? 0 }} / {{ payload.rule_count ?? 0 }}</strong>
          <small>{{ t("dns.status.enabled_total") }}</small>
        </div>
      </div>
    </div>

    <div class="surface table-surface">
      <div class="table-heading">
        <div>
          <h2>{{ t("resource_replace_page.list") }}</h2>
        </div>
      </div>
      <div class="table-inline-form upstream-add-form">
        <button type="button" class="btn" @click="backend.runAction('/backend/actions/reload-resource-replace')">
          {{ t("resource_replace_page.reload") }}
        </button>
      </div>
      <table>
        <thead>
          <tr>
            <th>{{ t("common.status") }}</th>
            <th>{{ t("common.host") }}</th>
            <th>{{ t("resource_replace_page.source") }}</th>
            <th>{{ t("common.file") }}</th>
            <th>{{ t("common.size") }}</th>
            <th>{{ t("common.action") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!payload.rules?.length">
            <td colspan="6">{{ t("resource_replace_page.none") }}</td>
          </tr>
          <tr v-for="item in payload.rules" :key="item.id">
            <td>{{ item.enabled ? t("common.enabled") : t("common.disabled") }}</td>
            <td class="mono">{{ item.hosts?.join(", ") || t("common.none") }}</td>
            <td class="mono">{{ item.source_regex || t("common.none") }}</td>
            <td class="mono">{{ item.file }} / {{ item.content_type }}</td>
            <td>{{ item.size }} {{ t("common.bytes") }}</td>
            <td>
              <button type="button" class="btn table-btn secondary" @click="toggle(item)">
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
      <p class="path-line mono">{{ payload.rule_dir }}</p>
    </div>
  </section>
</template>
