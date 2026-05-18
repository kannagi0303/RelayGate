<script setup lang="ts">
import { onMounted, watch } from "vue";
import { RouterLink, RouterView, useRoute } from "vue-router";
import { useI18n } from "vue-i18n";
import { useBackendStore } from "@/stores/backend";

const backend = useBackendStore();
const route = useRoute();
const { t } = useI18n();

onMounted(() => {
  backend.connect();
  void backend.refreshSnapshot();
});

watch(
  () => route.fullPath,
  () => {
    backend.clearFeedback();
    void backend.refreshSnapshot();
  },
);

type NavItem = {
  to: string;
  label: string;
};

type NavGroup = {
  titleKey: string;
  items: NavItem[];
};

const navGroups: NavGroup[] = [
  {
    titleKey: "nav.system",
    items: [
      { to: "/", label: "nav.status" },
      { to: "/settings", label: "nav.settings" },
    ],
  },
  {
    titleKey: "nav.connection_routing",
    items: [
      { to: "/dns", label: "nav.dns" },
      { to: "/connection-info", label: "nav.connection_info" },
      { to: "/upstreams", label: "nav.upstreams" },
      { to: "/upstream-routes", label: "nav.upstream_routes" },
      { to: "/gateway", label: "nav.gateway" },
    ],
  },
  {
    titleKey: "nav.content_processing",
    items: [
      { to: "/traffic", label: "nav.traffic" },
      { to: "/patch", label: "nav.patch" },
      { to: "/render", label: "nav.render" },
    ],
  },
  {
    titleKey: "nav.extensions",
    items: [
      { to: "/resource-replace", label: "nav.resource_replace" },
      { to: "/adblock", label: "nav.adblock" },
      { to: "/user-script", label: "nav.user_script" },
    ],
  },
];

function label(key: string) {
  return t(key);
}
</script>

<template>
  <div class="admin-shell">
    <aside class="admin-rail" :aria-label="t('app.admin_navigation')">
      <div class="brand-block">
        <div class="brand-mark" aria-hidden="true">RG</div>
        <div>
          <div class="brand-title">RelayGate</div>
          <div class="brand-status" :class="{ online: backend.connected }">
            {{ backend.connected ? t("app.online") : t("app.offline") }}
          </div>
        </div>
      </div>

      <nav class="nav-list">
        <template v-for="group in navGroups" :key="group.titleKey">
          <div class="nav-group-label">{{ t(group.titleKey) }}</div>
          <RouterLink
            v-for="item in group.items"
            :key="item.to"
            :to="item.to"
            class="nav-link"
          >
            {{ label(item.label) }}
          </RouterLink>
        </template>
      </nav>
    </aside>

    <main id="main-content" class="admin-main" tabindex="-1">
      <RouterView />
    </main>

    <div v-if="backend.feedback" class="toast-stack" aria-live="polite">
      <div class="toast-card" :class="backend.feedback.level">
        {{ backend.feedback.message }}
      </div>
    </div>
  </div>
</template>
