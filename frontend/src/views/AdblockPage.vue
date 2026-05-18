<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import { useBackendStore } from "@/stores/backend";
import MarkdownDoc from "@/components/MarkdownDoc.vue";

const backend = useBackendStore();
const { t } = useI18n();
const payload = computed(() => backend.adblock ?? {});
const helpMarkdown = computed(() => String(t("adblock.help.markdown")));

function updateMode(event: Event) {
  const target = event.target as HTMLInputElement;
  void backend.runAction("/backend/actions/update-setting", {
    key: "adblock.mode",
    value: target.value,
  });
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
          <h2>{{ t("common.desc") }}</h2>
        </div>
      </div>
      <MarkdownDoc :source="helpMarkdown" />
    </div>
  </section>
</template>
