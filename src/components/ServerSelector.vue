<script setup>
import { invoke } from "@tauri-apps/api/core"
import { emit } from "@tauri-apps/api/event"
import { onMounted, reactive, watch } from "vue"
import { fetch } from "@tauri-apps/plugin-http"

const props = defineProps({
  isAuthDone: {
    type: Boolean,
    default: false
  },
  isConnected: {
    type: Boolean,
    default: false
  },
  isConnectButtonLoading: {
    type: Boolean,
    default: false
  },
  isDark: {
    type: Boolean
  }
})
const state = reactive({
  isLoaded: false,
  hosts: [],
  ingressGateways: [],
  selectedNode: 0
})
const NETMAKER_API = "https://api.fabric.ophelia-matrix.net"
const NETMAKER_NETWORK = "ophelia-fabric"

watch(
  () => props.isAuthDone,
  async () => {
    if (props.isAuthDone) {
      await Promise.all([getHosts(), getIngressGateways()])
      await Promise.all([matchGatewayName(), matchHostPublicKey()])
      state.isLoaded = true
    }
  }
)

async function getHosts() {
  await fetch(`${NETMAKER_API}/api/hosts`, {
    headers: {
      Authorization: `Bearer ${await invoke("get_of_auth_token")}`
    }
  })
    .then((resp) => resp.json())
    .then((json) => (state.hosts = json))
}

async function getIngressGateways() {
  let nodes = await fetch(`${NETMAKER_API}/api/nodes/${NETMAKER_NETWORK}`, {
    headers: {
      Authorization: `Bearer ${await invoke("get_of_auth_token")}`
    }
  }).then(async (resp) => await resp.json())

  for (let index in nodes) {
    if (nodes[index].isingressgateway) {
      state.ingressGateways.push({
        address: nodes[index].address,
        allowedIp: nodes[index].egressgatewaynatenabled
          ? [nodes[index].networkrange].concat(nodes[index].egressgatewayranges)
          : [nodes[index].networkrange],
        hostId: nodes[index].hostid,
        nodeId: nodes[index].id,
        name: "",
        peerPublicKey: ""
      })
    }
  }
}

async function matchGatewayName() {
  for (let i in state.ingressGateways) {
    for (let j in state.hosts) {
      if (state.ingressGateways[i].hostId === state.hosts[j].id) {
        state.ingressGateways[i].name = state.hosts[j].name
        break
      }
    }
  }
}

async function matchHostPublicKey() {
  for (let i in state.ingressGateways) {
    for (let j in state.hosts) {
      if (state.hosts[j].id === state.ingressGateways[i].hostId) {
        state.ingressGateways[i].peerPublicKey = state.hosts[j].publickey
        break
      }
    }
  }
}

function onConnect() {
  emit("connect", {
    wgInfo: {
      peerPublicKey: state.ingressGateways[state.selectedNode].peerPublicKey,
      allowedIp: state.ingressGateways[state.selectedNode].allowedIp
    },
    ingressGateway: state.ingressGateways[state.selectedNode]
  })
}

function onDisconnect() {
  emit("disconnect")
}

onMounted(async () => {})
</script>

<template>
  <div class="app-container">
    <div class="server-select">
      <span class="server-select--prompt">Server to connect</span>
      <fluent-select
        class="server-select--selector"
        v-if="state.isLoaded"
        v-model="state.selectedNode"
        title="Select a server"
        placeholder="Select a server"
      >
        <fluent-option
          class="server-select--options"
          v-for="(ingressGateway, index) in state.ingressGateways"
          :value="index"
        >
          {{ ingressGateway.name }}
        </fluent-option>
      </fluent-select>

      <fluent-skeleton
        class="server-select--selector server-select--selector--skeleton"
        v-if="!state.isLoaded"
        shape="rect"
        shimmer
      />
    </div>

    <fluent-button
      class="connect-button"
      :disabled="!state.isLoaded || props.isConnectButtonLoading"
      appearance="accent"
      @click="props.isConnected ? onDisconnect() : onConnect()"
    >
      {{ props.isConnected ? "Disconnect" : "Connect" }}
    </fluent-button>
  </div>
</template>

<style scoped>
.app-container {
  max-width: 268px;
  width: 100%;
  display: flex;
  align-items: center;
  align-content: center;
  flex-direction: column;
}
.auth-failed-prompts {
  margin-bottom: 4px;
}
.server-select {
  width: 100%;
}
.server-select--prompt {
  font-size: 12px;
  line-height: 16px;
}
.server-select--selector {
  width: 100%;
  margin-top: 4px;
  margin-bottom: 4px;
}
.server-select--selector--skeleton {
  height: 32px;
}
.connect-button {
  margin-top: 4px;
  margin-bottom: 4px;
}
</style>
