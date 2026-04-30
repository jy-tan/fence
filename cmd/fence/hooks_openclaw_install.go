package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Use-Tusk/fence/internal/sandbox"
)

// openclawPluginPackageName is the published plugin; shared between tests
// and the print helper.
const openclawPluginPackageName = "@use-tusk/openclaw-fence"

// OpenClaw's plugin manager is imperative, so Fence editing the config
// file would only be half the work - the package still has to be fetched.
// We delegate to `openclaw plugins install` instead of coupling Fence to
// OpenClaw's CLI.
var (
	errOpenclawUseImperativeInstall = errors.New(
		"`fence hooks install --openclaw` is not supported because OpenClaw uses an imperative plugin manager; " +
			"run `openclaw plugins install " + openclawPluginPackageName + "` instead, then restart the gateway " +
			"(see `fence hooks print --openclaw` for the full instructions)",
	)
	errOpenclawUseImperativeUninstall = errors.New(
		"`fence hooks uninstall --openclaw` is not supported; " +
			"run `openclaw plugins uninstall openclaw-fence` instead",
	)
)

// writeOpenclawHooksGuidance prints the install one-liner, plus optional
// settings/template advice. Print-only by design - the install itself
// stays on the OpenClaw side.
func writeOpenclawHooksGuidance(w io.Writer, hookOptions hookFenceOptions) error {
	var b strings.Builder
	b.WriteString("# OpenClaw uses an imperative plugin manager.\n")
	b.WriteString("# Run:\n")
	fmt.Fprintf(&b, "openclaw plugins install %s\n", openclawPluginPackageName)
	b.WriteString("openclaw gateway restart\n")

	if hookOptions.SettingsPath != "" || hookOptions.TemplateName != "" {
		b.WriteString("\n")
		b.WriteString("# To pin a Fence config or template, set plugin options after install:\n")
		b.WriteString("# (in your OpenClaw config under plugins.entries.openclaw-fence.config)\n")
		if hookOptions.SettingsPath != "" {
			fmt.Fprintf(&b, "#   settingsPath: %s\n", sandbox.ShellQuote([]string{hookOptions.SettingsPath}))
		}
		if hookOptions.TemplateName != "" {
			fmt.Fprintf(&b, "#   template: %s\n", hookOptions.TemplateName)
		}
	} else {
		b.WriteString("\n")
		b.WriteString("# Recommended: also pin the bundled `openclaw` template:\n")
		b.WriteString("#   plugins.entries.openclaw-fence.config.template: openclaw\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}
