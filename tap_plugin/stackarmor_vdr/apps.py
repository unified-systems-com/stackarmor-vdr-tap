"""TAP StackArmor VDR plugin AppConfig."""

from tap_plugins.base import TapPluginConfig


class StackarmorVdrConfig(TapPluginConfig):
    """No collectors: the plugin ships two models, two edges, a seed, four Search runners and one panel type."""

    def ready(self) -> None:
        # Base ready() loads tap-plugin.toml and registers the plugin's models, edges and Searches.
        super().ready()

        # The prose panel type (req-stackarmor-vdr-panel-prose). Registered in ready(), after every app has loaded.
        from tap_plugin.stackarmor_vdr.panels.prose import StackarmorProsePanelType

        from tap_web.registry import panel_type_registry

        panel_type_registry.register(StackarmorProsePanelType.slug, StackarmorProsePanelType)

        # The finding walk-through panel type (req-stackarmor-vdr-panel-finding).
        from tap_plugin.stackarmor_vdr.panels.finding import StackarmorFindingPanelType

        panel_type_registry.register(StackarmorFindingPanelType.slug, StackarmorFindingPanelType)

        # The cleaned-HTML panel type (req-stackarmor-vdr-panel-html).
        from tap_plugin.stackarmor_vdr.panels.html_panel import StackarmorHtmlPanelType

        panel_type_registry.register(StackarmorHtmlPanelType.slug, StackarmorHtmlPanelType)
