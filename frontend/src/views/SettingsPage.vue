<script setup lang="ts">
import { computed, reactive, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { useBackendStore } from "@/stores/backend";

const backend = useBackendStore();
const { t } = useI18n();
const settings = computed(() => backend.settings ?? {});
const mitm = computed(() => settings.value.mitm ?? {});
const protocolForm = reactive({
  upstream_protocol: "guarded_h3",
  downstream_protocol: "http2_enabled",
});
const protocolSaving = ref(false);
const protocolSaveQueued = ref(false);

const caFileText = computed(() => {
  const certOk = mitm.value.ca_cert_exists === true;
  const keyOk = mitm.value.ca_key_exists === true;
  if (certOk && keyOk) return t("settings_page.ca.file_ready");
  if (certOk || keyOk) return t("settings_page.ca.file_partial");
  return t("settings_page.ca.file_missing");
});

const caTrustText = computed(() => {
  if (mitm.value.windows_user_root_trusted === true) return t("settings_page.ca.trusted");
  if (mitm.value.windows_user_root_trusted === false) return t("settings_page.ca.untrusted");
  return t("settings_page.ca.unknown");
});

const windowsCas = computed(() => mitm.value.windows_relaygate_cas ?? []);

function run(endpoint: string) {
  void backend.runAction(endpoint);
}

function removeWindowsCa(id: string) {
  void backend.runAction("/backend/actions/remove-windows-relaygate-ca", { id });
}

watch(
  () => settings.value.protocol,
  (protocol) => {
    if (protocolSaving.value) {
      return;
    }

    protocolForm.upstream_protocol = protocol?.upstream_preferred || "guarded_h3";
    protocolForm.downstream_protocol = protocol?.downstream_preferred || "http2_enabled";
  },
  { immediate: true },
);

async function saveProtocolSettings() {
  if (protocolSaving.value) {
    protocolSaveQueued.value = true;
    return;
  }

  protocolSaving.value = true;
  try {
    do {
      protocolSaveQueued.value = false;
      await backend.runAction("/backend/actions/update-protocol-settings", {
        upstream_protocol: protocolForm.upstream_protocol,
        downstream_protocol: protocolForm.downstream_protocol,
      });
    } while (protocolSaveQueued.value);
  } finally {
    protocolSaving.value = false;
  }
}

function onProtocolChange() {
  void saveProtocolSettings();
}

function updateLocale(event: Event) {
  const target = event.target as HTMLSelectElement;
  void backend.runAction("/backend/actions/update-setting", {
    key: "locale",
    value: target.value,
  });
}
</script>

<template>
  <section class="page-stack">
    <header class="page-header">
      <p class="eyebrow">{{ t("nav.system") }}</p>
      <h1>{{ t("settings_page.title") }}</h1>
      <p class="page-copy">{{ t("settings_page.intro") }}</p>
    </header>

    <div class="surface action-panel">
      <h2>{{ t("settings_page.language.title") }}</h2>
      <p>{{ t("settings_page.language.body") }}</p>
      <label>
        <span>{{ t("settings.locale.label") }}</span>
        <select :value="settings.locale || 'en-US'" @change="updateLocale">
          <option v-for="locale in settings.available_locales || []" :key="locale" :value="locale">
            {{ t(`settings_page.language.option.${locale}`) }}
          </option>
        </select>
      </label>
    </div>

    <div class="surface action-panel">
      <h2>{{ t("settings_page.protocol.title") }}</h2>
      <p>{{ t("settings_page.protocol.body") }}</p>
      <p class="inline-note">{{ t("settings_page.protocol.apply_note") }}</p>
      <div class="form-grid two protocol-grid compact-form">
        <label>
          <span>{{ t("settings_page.protocol.upstream_limit") }}</span>
          <select
            v-model="protocolForm.upstream_protocol"
            :disabled="protocolSaving"
            @change="onProtocolChange"
          >
            <option value="guarded_h3">{{ t("settings_page.protocol.option_guarded_h3") }}</option>
            <option value="http2_preferred">{{ t("settings_page.protocol.option_http2_http1") }}</option>
          </select>
          <small>{{ t("settings_page.protocol.upstream_note") }}</small>
        </label>
        <label>
          <span>{{ t("settings_page.protocol.downstream") }}</span>
          <select
            v-model="protocolForm.downstream_protocol"
            :disabled="protocolSaving"
            @change="onProtocolChange"
          >
            <option value="http2_enabled">{{ t("settings_page.protocol.option_http2_enabled") }}</option>
            <option value="http1_only">{{ t("settings_page.protocol.option_http1_only") }}</option>
          </select>
          <small>{{ t("settings_page.protocol.downstream_note") }}</small>
        </label>
      </div>
    </div>

    <div class="surface action-panel">
      <h2>{{ t("settings_page.ca.title") }}</h2>
      <p>{{ t("settings_page.ca.body") }}</p>
      <div class="metric-row compact-row">
        <span>{{ t("settings_page.ca.file") }}</span>
        <strong>{{ caFileText }}</strong>
      </div>
      <div class="metric-row compact-row">
        <span>{{ t("settings_page.ca.windows_user_root") }}</span>
        <strong>{{ caTrustText }}</strong>
      </div>
      <div class="metric-row compact-row">
        <span>{{ t("settings_page.ca.cert_path") }}</span>
        <strong class="mono">{{ mitm.ca_cert_path || t("common.none") }}</strong>
      </div>
      <div class="actions">
        <button type="button" class="btn" @click="run('/backend/actions/create-ca')">
          {{ t("ca.trust.install") }}
        </button>
        <button type="button" class="btn secondary" @click="run('/backend/actions/remove-ca-trust')">
          {{ t("ca.trust.remove") }}
        </button>
      </div>

      <h3>{{ t("settings_page.ca.windows_list_title") }}</h3>
      <p class="inline-note">{{ t("settings_page.ca.windows_list_note") }}</p>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>{{ t("settings_page.ca.table.store") }}</th>
              <th>{{ t("settings_page.ca.table.identity") }}</th>
              <th>{{ t("settings_page.ca.table.thumbprint") }}</th>
              <th>{{ t("settings_page.ca.table.expires") }}</th>
              <th>{{ t("settings_page.ca.table.action") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="windowsCas.length === 0">
              <td colspan="5">{{ t("settings_page.ca.no_windows_ca") }}</td>
            </tr>
            <tr v-for="item in windowsCas" :key="item.id">
              <td>{{ item.store }}</td>
              <td>
                <strong>{{ item.is_current ? t("settings_page.ca.current_ca") : t("settings_page.ca.other_ca") }}</strong>
                <small class="block-note mono">{{ item.subject }}</small>
              </td>
              <td class="mono">{{ item.thumbprint }}</td>
              <td>{{ item.not_after }}</td>
              <td>
                <button type="button" class="btn small danger" @click="removeWindowsCa(item.id)">
                  {{ t("settings_page.ca.remove_this") }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="surface action-panel danger-panel">
      <h2>{{ t("settings_page.exit.title") }}</h2>
      <p>{{ t("settings_page.exit.body") }}</p>
      <div class="actions">
        <button type="button" class="btn danger" @click="run('/backend/actions/exit')">
          {{ t("settings_page.actions.exit") }}
        </button>
      </div>
    </div>
  </section>
</template>
