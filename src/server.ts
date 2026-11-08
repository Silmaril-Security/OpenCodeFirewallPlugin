const plugin = {
  id: "silmaril-firewall",
  server: async (
    input: Parameters<typeof import("./index.js").SilmarilFirewallPlugin>[0],
    options: Parameters<typeof import("./index.js").SilmarilFirewallPlugin>[1],
  ) => (await import("./index.js")).SilmarilFirewallPlugin(input, options),
  setup: async (
    context: Parameters<typeof import("./v2.js").setup>[0],
  ) => (await import("./v2.js")).setup(context),
};

export default plugin;
