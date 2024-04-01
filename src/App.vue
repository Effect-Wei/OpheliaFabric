<script setup>
import { onMounted, reactive, watch } from "vue"
import { fetch } from "@tauri-apps/plugin-http"
import { invoke } from "@tauri-apps/api/core"
import { listen } from "@tauri-apps/api/event"
import { getCurrent } from "@tauri-apps/api/window"
import { baseLayerLuminance, StandardLuminance } from "@fluentui/web-components"
import TitleBar from "./components/TitleBar.vue"
import ServerSelector from "./components/ServerSelector.vue"

const state = reactive({
  isAuthDone: false,
  isAuthFailed: false,
  isConnected: false,
  isConnectButtonLoading: false,
  isDark: true,
  isUpdated: true,
  authInfo: "",
  extClient: {
    id: "",
    privateKey: "",
    internalIp: "",
    endpoint: ""
  },
  ingressGateway: {},
  wgInfo: {
    peerPublicKey: "",
    allowedIp: ""
  },
  wgStatistics: {
    up: 0,
    down: 0,
    handshakeAge: 0
  }
})
const NETMAKER_API = "https://api.fabric.ophelia-matrix.net"
const NETMAKER_NETWORK = "ophelia-fabric"
const ID_LENGTH = 15

watch(
  () => state.isDark,
  () => {
    baseLayerLuminance.withDefault(
      state.isDark ? StandardLuminance.DarkMode : StandardLuminance.LightMode
    )
  },
  { immediate: true }
)

function generateId(len) {
  let arr = new Uint8Array((len || 40) / 2)
  window.crypto.getRandomValues(arr)
  return Array.from(arr, (dec) => {
    return dec.toString(16).padStart(2, "0")
  }).join("")
}

async function initListeners() {
  listen("connect", async (event) => {
    state.wgInfo = event.payload.wgInfo
    state.ingressGateway = event.payload.ingressGateway
    await connectWg()
  })

  listen("disconnect", async () => {
    await disconnectWg()
  })

  listen("wg-statistics", (event) => {
    state.wgStatistics = {
      up: event.payload.up,
      down: event.payload.down,
      handshakeAge: event.payload.handshake_age
    }
    console.log(state.wgStatistics)
  })

  listen("close", async () => {
    if (state.isConnected) {
      await disconnectWg()
    }
    await getCurrent().close()
  })
}

async function createExtClient() {
  state.extClient.id = generateId(ID_LENGTH)
  let extClientResp = await fetch(
    `${NETMAKER_API}/api/extclients/${NETMAKER_NETWORK}/${state.ingressGateway.nodeId}`,
    {
      method: "POST",
      body: JSON.stringify({
        clientid: state.extClient.id,
        enabled: true
      }),
      headers: {
        Authorization: `Bearer ${await invoke("get_of_auth_token")}`
      }
    }
  )

  if (!extClientResp.ok) {
    throw "Failed to create extClient!"
  }
}

async function getExtClient() {
  await fetch(
    `${NETMAKER_API}/api/extclients/${NETMAKER_NETWORK}/${state.extClient.id}`,
    {
      headers: {
        Authorization: `Bearer ${await invoke("get_of_auth_token")}`
      }
    }
  ).then(async (resp) => {
    if (!resp.ok) {
      throw "Failed to get extClient!"
    }
    let json = await resp.json()
    state.extClient.privateKey = json.privatekey
    state.extClient.internalIp = json.address
    state.extClient.endpoint = json.ingressgatewayendpoint
  })
}

async function deleteExtClient() {
  let extClientResp = await fetch(
    `${NETMAKER_API}/api/extclients/${NETMAKER_NETWORK}/${state.extClient.id}`,
    {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${await invoke("get_of_auth_token")}`
      }
    }
  )

  if (!extClientResp.ok) {
    throw "Failed to delete extClient!"
  }
}

async function connectWg() {
  state.isConnectButtonLoading = true
  await createExtClient()
  await getExtClient()
  await invoke("wg_connect", {
    privateKey: state.extClient.privateKey,
    peerPublicKey: state.ingressGateway.peerPublicKey,
    internalIp: state.extClient.internalIp,
    endpoint: state.extClient.endpoint,
    allowedIp: state.ingressGateway.allowedIp
  })

  state.isConnected = true
  state.isConnectButtonLoading = false
}

async function disconnectWg() {
  state.isConnectButtonLoading = true
  await invoke("wg_disconnect")
  await deleteExtClient().catch(() => {})
  state.wgStatistics = {
    up: 0,
    down: 0,
    handshakeAge: 0
  }
  state.isConnected = false
  state.isConnectButtonLoading = false
}

onMounted(async () => {
  await getCurrent().onThemeChanged(({ payload: theme }) => {
    state.isDark = theme === "dark" ? true : false
  })

  console.log("Hi Ophelia!")
  console.log("Initiating authentication sequence...")

  initListeners()
  await invoke("init_of_auth_token")
    .then(() => {
      state.isAuthDone = true
    })
    .catch((e) => {
      state.authInfo = e
      state.isAuthFailed = true
    })

  console.log("Authentication sequence finished.")
})
</script>

<template>
  <title-bar :is-dark="state.isDark" />
  <div class="main-container">
    <!--
    <update-checker
      v-if="!state.isUpdated"
      :is-dark="state.isDark"
      @of-updated="state.isUpdated = true"
    />
    -->
    <span
      v-if="state.isAuthFailed"
      class="auth-failed-prompts"
    >
      Auth Failed! {{ state.authInfo }}
      Please restart app or report this issue to us.
    </span>
    <server-selector
      v-if="state.isUpdated"
      :is-dark="state.isDark"
      :is-auth-done="state.isAuthDone"
      :is-connected="state.isConnected"
      :is-connect-button-loading="state.isConnectButtonLoading"
    />
  </div>
</template>

<style scoped>
.main-container {
  margin-top: 48px;
  padding: 0px 16px 16px 16px;
  max-width: 268px;
  width: 100%;
  display: flex;
  justify-content: center;
  align-items: center;
  align-content: center;
  flex-direction: column;
}
</style>
