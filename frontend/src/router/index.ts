import { createRouter, createWebHistory } from "vue-router";
import StatusPage from "@/views/StatusPage.vue";
import SettingsPage from "@/views/SettingsPage.vue";
import UserScriptPage from "@/views/UserScriptPage.vue";
import AdblockPage from "@/views/AdblockPage.vue";
import DnsPage from "@/views/DnsPage.vue";
import GatewayPage from "@/views/GatewayPage.vue";
import ResourceReplacePage from "@/views/ResourceReplacePage.vue";
import SimpleRuntimePage from "@/views/SimpleRuntimePage.vue";
import TrafficPage from "@/views/TrafficPage.vue";
import ConnectionInfoPage from "@/views/ConnectionInfoPage.vue";
import UpstreamRoutesPage from "@/views/UpstreamRoutesPage.vue";
import UpstreamsPage from "@/views/UpstreamsPage.vue";

export const router = createRouter({
  history: createWebHistory("/"),
  routes: [
    { path: "/", name: "status", component: StatusPage },
    { path: "/settings", name: "settings", component: SettingsPage },
    { path: "/gateway", name: "gateway", component: GatewayPage },
    { path: "/upstreams", name: "upstreams", component: UpstreamsPage },
    { path: "/upstream-routes", name: "upstream-routes", component: UpstreamRoutesPage },
    { path: "/dns", name: "dns", component: DnsPage },
    { path: "/traffic", name: "traffic", component: TrafficPage },
    { path: "/connection-info", name: "connection-info", component: ConnectionInfoPage },
    { path: "/patch", name: "patch", component: SimpleRuntimePage, props: { page: "patch" } },
    { path: "/render", name: "render", component: SimpleRuntimePage, props: { page: "render" } },
    { path: "/resource-replace", name: "resource-replace", component: ResourceReplacePage },
    { path: "/adblock", name: "adblock", component: AdblockPage },
    { path: "/user-script", name: "user-script", component: UserScriptPage },
  ],
});
