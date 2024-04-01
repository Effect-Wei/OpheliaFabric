import { createApp } from "vue"
import {
  provideFluentDesignSystem,
  fluentButton,
  fluentCard,
  fluentOption,
  fluentProgressRing,
  fluentSelect,
  fluentSkeleton
} from "@fluentui/web-components"
import "./styles.css"
import App from "./App.vue"

const app = createApp(App)

function disableMenu() {
  if (window.location.hostname !== "tauri.localhost") {
    return
  }

  document.addEventListener(
    "contextmenu",
    (e) => {
      e.preventDefault()
      return false
    },
    { capture: true }
  )

  document.addEventListener(
    "selectstart",
    (e) => {
      e.preventDefault()
      return false
    },
    { capture: true }
  )
}

disableMenu()
provideFluentDesignSystem().register(
  fluentButton(),
  fluentCard(),
  fluentOption(),
  fluentProgressRing(),
  fluentSelect(),
  fluentSkeleton()
)
app.mount("#app")
