<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import { useBackendStore } from "@/stores/backend";
import MarkdownDoc from "@/components/MarkdownDoc.vue";

const backend = useBackendStore();
const { t } = useI18n();
const payload = computed(() => backend.adblock ?? { files: [], resource_files: [] });
const helpMarkdown = computed(() => String(t("adblock.help.markdown")));

function updateMode(event: Event) {
  const target = event.target as HTMLInputElement;
  void backend.runAction("/backend/actions/update-setting", {
    key: "adblock.mode",
    value: target.value,
  });
}

function updateDisableFastPath(event: Event) {
  const target = event.target as HTMLInputElement;
  void backend.runAction("/backend/actions/update-setting", {
    key: "proxy.mitm.disable_fast_path",
    value: target.checked ? "true" : "false",
  });
}

function updateDebugLog(event: Event) {
  const target = event.target as HTMLInputElement;
  void backend.runAction("/backend/actions/update-setting", {
    key: "adblock.debug_log",
    value: target.checked ? "true" : "false",
  });
}

function reloadAdblockRules() {
  void backend.runAction("/backend/actions/reload-adblock-rules");
}

function openAdblockRulesFolder() {
  void backend.runAction("/backend/actions/open-adblock-rules-folder");
}
</script>

<template>
  <section class="page-stack">
    <header class="page-header">
      <p class="eyebrow">{{ t("nav.extensions") }}</p>
      <h1>{{ t("nav.adblock") }}</h1>
      <p class="page-copy">{{ t("adblock.page.sub") }}</p>
      <p class="page-copy small-copy">{{ t("adblock.page.apply_note") }}</p>
    </header>

    <div class="surface summary-panel">
      <div class="summary-list dns-summary-list">
      <div class="summary-item">
        <span>{{ t("adblock.feature") }}</span>
        <strong>{{ payload.mode_label || t("common.none") }}</strong>
      </div>
      <div class="summary-item">
        <span>{{ t("adblock.rules.label") }}</span>
        <strong>{{ payload.rule_count ?? 0 }}</strong>
      </div>
      <div class="summary-item">
        <span>{{ t("adblock.resources.label") }}</span>
        <strong>{{ payload.resource_count ?? 0 }}</strong>
      </div>
      </div>
    </div>

    <div class="surface action-panel">
      <div class="table-heading">
        <div>
          <h2>{{ t("settings.adblock.label") }}</h2>
        </div>
      </div>
      <fieldset class="radio-group">
        <legend>{{ t("adblock.feature") }}</legend>
        <p class="field-note">{{ t("settings.adblock.note") }}</p>
        <label class="radio-option">
          <input
            type="radio"
            name="adblock-mode"
            value="disabled"
            :checked="payload.mode_value === 'disabled'"
            @change="updateMode"
          />
          <span>{{ t("adblock.mode.off") }}</span>
        </label>
        <label class="radio-option">
          <input
            type="radio"
            name="adblock-mode"
            value="standard"
            :checked="payload.mode_value === 'standard'"
            @change="updateMode"
          />
          <span>{{ t("adblock.mode.std") }}</span>
        </label>
        <label class="radio-option">
          <input
            type="radio"
            name="adblock-mode"
            value="aggressive"
            :checked="!payload.mode_value || payload.mode_value === 'aggressive'"
            @change="updateMode"
          />
          <span>{{ t("adblock.mode.agg") }}</span>
        </label>
      </fieldset>
    </div>

    <div class="surface action-panel">
      <div class="table-heading">
        <div>
          <h2>{{ t("adblock.troubleshooting.title") }}</h2>
        </div>
      </div>
      <label class="check-row">
        <input
          type="checkbox"
          role="switch"
          :checked="payload.disable_mitm_fast_path === true"
          @change="updateDisableFastPath"
        />
        <span>{{ t("adblock.troubleshooting.disable_fast_path") }}</span>
      </label>
      <p class="field-note">
        {{ t("adblock.troubleshooting.fast_path_note") }}
      </p>
      <label class="check-row">
        <input
          type="checkbox"
          role="switch"
          :checked="payload.debug_log_enabled === true"
          @change="updateDebugLog"
        />
        <span>{{ t("adblock.troubleshooting.debug_log") }}</span>
      </label>
      <p class="field-note">
        {{ t("adblock.troubleshooting.debug_log_note") }}
      </p>
    </div>

    <div class="surface action-panel">
      <div class="table-heading">
        <div>
          <h2>{{ t("adblock.custom_rules.title") }}</h2>
        </div>
      </div>
      <p class="field-note">
        {{ t("adblock.custom_rules.note", { file: payload.custom_rule_file || "data/adblock/custom.txt" }) }}
      </p>
      <div class="actions">
        <button type="button" class="btn" @click="openAdblockRulesFolder">{{ t("adblock.custom_rules.open_folder") }}</button>
        <button type="button" class="btn" @click="reloadAdblockRules">{{ t("adblock.custom_rules.reload") }}</button>
      </div>
    </div>

    <div class="surface action-panel">
      <div class="table-heading">
        <div>
          <h2>{{ t("adblock.update.label") }}</h2>
        </div>
      </div>
      <p>{{ t("adblock.update.note") }}</p>
      <p class="field-note">
        {{ t("adblock.update.brave_note") }}
      </p>
      <button type="button" class="btn" @click="backend.runAction('/backend/actions/update-adblock-lists')">
        {{ t("adblock.update.now") }}
      </button>
    </div>

    <div class="surface table-surface">
      <div class="table-heading">
        <div>
          <h2>{{ t("adblock.rules.label") }}</h2>
        </div>
      </div>
      <table>
        <thead>
          <tr>
            <th>{{ t("common.file") }}</th>
            <th>{{ t("adblock.rules.source") }}</th>
            <th>{{ t("adblock.rules.tags") }}</th>
            <th>{{ t("common.size") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!payload.files?.length">
            <td colspan="4">{{ t("adblock.rules.none") }}</td>
          </tr>
          <tr v-for="file in payload.files" :key="file.name">
            <td class="mono">{{ file.name }}</td>
            <td>
              <span>{{ file.title || file.source_url || "—" }}</span>
              <div v-if="file.source_url" class="field-note mono">{{ file.source_url }}</div>
            </td>
            <td>
              <span v-if="file.tags?.length" class="tag-list">
                <span v-for="tag in file.tags" :key="tag" class="pill">{{ tag }}</span>
              </span>
              <span v-else>—</span>
            </td>
            <td>{{ file.size }} {{ t("common.bytes") }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="surface table-surface">
      <div class="table-heading">
        <div>
          <h2>{{ t("adblock.resources.label") }}</h2>
        </div>
      </div>
      <table>
        <thead>
          <tr>
            <th>{{ t("adblock.resources.label") }}</th>
            <th>{{ t("adblock.resources.source") }}</th>
            <th>{{ t("common.size") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!payload.resource_files?.length">
            <td colspan="3">{{ t("adblock.resources.none") }}</td>
          </tr>
          <tr v-for="file in payload.resource_files" :key="file.name">
            <td class="mono">{{ file.name }}</td>
            <td>
              <span>{{ file.title || "—" }}</span>
              <div v-if="file.source_url" class="field-note mono">{{ file.source_url }}</div>
            </td>
            <td>{{ file.size }} {{ t("common.bytes") }}</td>
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

<style scoped>
.tag-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem;
}
.pill {
  border: 1px solid var(--border-color, rgba(148, 163, 184, 0.35));
  border-radius: 999px;
  padding: 0.1rem 0.45rem;
  font-size: 0.78rem;
  white-space: nowrap;
}
</style>
