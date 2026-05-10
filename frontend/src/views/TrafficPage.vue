<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import { useBackendStore } from "@/stores/backend";
import MarkdownDoc from "@/components/MarkdownDoc.vue";

const backend = useBackendStore();
const { t } = useI18n();
const payload = computed(() => backend.traffic ?? { hosts: [] });
const helpMarkdown = computed(() => String(t("traffic_page.help.markdown")));
</script>

<template>
  <section class="page-stack">
    <header class="page-header">
      <p class="eyebrow">{{ t("nav.content_processing") }}</p>
      <h1>{{ t("traffic_page.title") }}</h1>
      <p class="page-copy">{{ t("traffic_page.sub") }}</p>
    </header>

    <div class="surface summary-panel">
      <div class="summary-list dns-summary-list">
        <div class="summary-item"><span>{{ t("traffic_page.mode") }}</span><strong>{{ payload.enabled ? t("common.enabled") : t("common.disabled") }}</strong></div>
        <div class="summary-item"><span>{{ t("traffic_page.active") }}</span><strong>{{ payload.active_requests ?? 0 }}</strong></div>
        <div class="summary-item"><span>{{ t("traffic_page.queued") }}</span><strong>{{ payload.queued_requests ?? 0 }}</strong></div>
      </div>
    </div>

    <div class="surface table-surface">
      <div class="table-heading">
        <div>
          <h2>{{ t("traffic_page.strategy") }}</h2>
        </div>
      </div>
      <div class="metric-row"><span>{{ t("traffic_page.cooldown") }}</span><strong>{{ payload.initial_cooldown_secs ?? 0 }}s</strong></div>
      <div class="metric-row"><span>{{ t("traffic_page.interval") }}</span><strong>{{ payload.initial_release_interval_secs ?? 0 }}s</strong></div>
      <div class="metric-row"><span>{{ t("traffic_page.max_queue") }}</span><strong>{{ payload.max_queue_per_host ?? 0 }}</strong></div>
      <div class="metric-row"><span>{{ t("traffic_page.hosts") }}</span><strong>{{ payload.controlled_hosts ?? 0 }}</strong></div>
    </div>

    <div class="surface table-surface">
      <div class="table-heading">
        <div>
          <h2>{{ t("traffic_page.host.title") }}</h2>
        </div>
      </div>
      <table>
        <thead>
          <tr>
            <th>{{ t("common.host") }}</th>
            <th>{{ t("traffic_page.host.in_flight") }}</th>
            <th>{{ t("traffic_page.host.queued") }}</th>
            <th>{{ t("common.cooldown") }}</th>
            <th>{{ t("common.latest") }}</th>
            <th>{{ t("common.learned") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!payload.hosts?.length">
            <td colspan="6">{{ t("traffic_page.host.none") }}</td>
          </tr>
          <tr v-for="host in payload.hosts" :key="host.host">
            <td class="mono">{{ host.host }}</td>
            <td>{{ host.active_requests }}</td>
            <td>{{ host.queued_requests }}</td>
            <td>{{ host.cooldown_text }}</td>
            <td>{{ host.last_status_text }}</td>
            <td>{{ host.learned_text }}</td>
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
