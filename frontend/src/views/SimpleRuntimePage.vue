<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import { useBackendStore } from "@/stores/backend";
import MarkdownDoc from "@/components/MarkdownDoc.vue";

const props = defineProps<{ page: "patch" | "render" }>();
const backend = useBackendStore();
const { t } = useI18n();
const payload = computed(() => (props.page === "patch" ? backend.patch : backend.render) ?? {});
const titleKey = computed(() => (props.page === "patch" ? "patch_page.title" : "render_page.title"));
const subKey = computed(() => (props.page === "patch" ? "patch_page.sub" : "render_page.sub"));
const helpKey = computed(() => (props.page === "patch" ? "patch_page.help.markdown" : "render_page.help.markdown"));
const helpMarkdown = computed(() => String(t(helpKey.value)));
</script>

<template>
  <section class="page-stack">
    <header class="page-header">
      <p class="eyebrow">{{ t("nav.content_processing") }}</p>
      <h1>{{ t(titleKey) }}</h1>
      <p class="page-copy">{{ t(subKey) }}</p>
    </header>

    <div class="surface table-surface">
      <div class="table-heading">
        <div>
          <h2>{{ t("rewrite_page.title") }}</h2>
        </div>
      </div>
      <div class="table-inline-form upstream-add-form">
        <button type="button" class="btn" @click="backend.runAction('/backend/actions/reload-rules')">
          {{ t("rewrite_page.reload") }}
        </button>
      </div>
    </div>

    <div class="surface table-surface">
      <div class="table-heading">
        <div>
          <h2>{{ props.page === "patch" ? t("patch_page.current") : t("render_page.current") }}</h2>
        </div>
      </div>
      <div class="metric-row">
        <span>{{ props.page === "patch" ? t("patch_page.path") : t("render_page.path") }}</span>
        <strong class="mono">{{ payload.rule_dir || t("common.none") }}</strong>
      </div>
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
