import type { Plugin } from "@opencode/plugin/tui";

const PLUGIN_ID = "opencode-firewall-plugin";

export const SilmarilFirewallTuiPlugin: Plugin.Definition = {
  id: PLUGIN_ID,
  setup(api) {
    api.keymap.layer(() => ({
      mode: "global",
      commands: [
        {
          id: "silmaril.firewall.status",
          title: "Silmaril Firewall",
          group: "Plugin",
          palette: true,
          slash: {
            name: "silmaril-firewall",
          },
          run() {
            api.ui.toast.show({
              variant: "info",
              title: "Silmaril Firewall",
              message: "Blocked decisions are shown inline in the current session transcript.",
            });
          },
        },
      ],
    }));
  },
};

export default SilmarilFirewallTuiPlugin;
