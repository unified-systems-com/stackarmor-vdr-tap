"""TAP StackArmor VDR plugin AppConfig."""

from tap_plugins.base import TapPluginConfig


class StackarmorVdrConfig(TapPluginConfig):
    """No collectors or panels: the plugin ships two models, two edges, a seed and two Search runners."""
