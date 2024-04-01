<script setup>
import { getCurrent } from "@tauri-apps/api/window"
import { emit } from "@tauri-apps/api/event"
import OFIcon from "/src/assets/of-icon.png"

const props = defineProps({
  isDark: {
    type: Boolean
  }
})
</script>

<template>
  <div
    data-tauri-drag-region
    class="titlebar"
  >
    <div
      data-tauri-drag-region
      class="title-and-icon"
    >
      <img
        data-tauri-drag-region
        class="icon"
        :src="OFIcon"
        alt="OF Icon"
      />

      <span
        data-tauri-drag-region
        class="title"
      >
        Ophelia Fabric
      </span>
    </div>

    <div class="caption-buttons">
      <span
        class="titlebar-button"
        id="titlebar-minimize"
        @click="getCurrent().minimize()"
      >
        &#xE921;
      </span>

      <span
        class="titlebar-button"
        id="titlebar-close"
        @click="emit('close')"
      >
        &#xE8BB;
      </span>
    </div>
  </div>
</template>

<style scoped>
.titlebar {
  height: 48px;
  user-select: none;
  display: flex;
  align-items: center;
  justify-content: space-between;
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
}
.title-and-icon {
  display: flex;
  align-items: center;
}
.icon {
  margin: 14px 4px 14px 12px;
  height: 20px;
  width: 20px;
}
.title {
  margin: 0 4px;
  font-size: 12px;
  line-height: 16px;
}
.titlebar-button {
  display: inline-flex;
  justify-content: center;
  align-items: center;
  width: 48px;
  height: 48px;
  font-family: "Segoe MDL2 Assets";
  font-size: 10px;
  transition: background 0.15s ease-in-out;
}
#titlebar-minimize:hover {
  background: #ffffff22;
}
#titlebar-close:hover {
  background: #ff0000;
}
</style>
