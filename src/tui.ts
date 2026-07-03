import type { TuiPlugin, TuiPluginModule } from "@opencode-ai/plugin/tui";

const PLUGIN_ID = "opencode-firewall-plugin";

export const SilmarilFirewallTuiPlugin: TuiPlugin = async (api) => {
  api.keymap.registerLayer({
    commands: [
      {
        name: "silmaril.firewall.status",
        title: "Silmaril Firewall",
        category: "Plugin",
        namespace: "palette",
        slashName: "silmaril-firewall",
        run() {
          api.ui.toast({
            variant: "info",
            title: "Silmaril Firewall",
            message: "Blocked decisions are shown inline in the current session transcript.",
          });
        },
      },
    ],
  });
};

const pluginModule: TuiPluginModule & { id: string } = {
  id: PLUGIN_ID,
  tui: SilmarilFirewallTuiPlugin,
};

export default pluginModule;
