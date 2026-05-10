<script setup lang="ts">
import { computed } from "vue";
import { renderMarkdown } from "@/lib/markdown";

const props = defineProps<{
  source: string;
}>();

const renderedHtml = computed(() => renderMarkdown(props.source));
</script>

<template>
  <div class="doc-markdown" v-html="renderedHtml" />
</template>
