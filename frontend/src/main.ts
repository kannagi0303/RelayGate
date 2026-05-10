import { createApp } from "vue";
import { createPinia } from "pinia";
import App from "./App.vue";
import { router } from "./router";
import { i18n, loadInitialI18n } from "./plugins/i18n";
import "./styles/tokens.css";
import "./styles/app.css";

const root = document.documentElement;
root.dataset.theme = "dark";
root.classList.add("rg-theme-dark");
root.style.colorScheme = "dark";

loadInitialI18n().finally(() => {
  createApp(App).use(createPinia()).use(router).use(i18n).mount("#app");
});
