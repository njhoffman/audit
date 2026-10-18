package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/njhoffman/audit/internal/config"
)

func newConfigCmd(a *app) *cobra.Command {
	var (
		initFile bool
		force    bool
		pathOnly bool
	)
	c := &cobra.Command{
		Use:   "config",
		Short: "Show the effective configuration or rewrite the default file",
		Long: `Print the configuration in effect (defaults, the YAML file and AUDIT_*
environment variables merged). The default file is created with every
setting at its default on the first run of any command. --init writes that
file again to the default location, or to --config when given.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			path := a.flags.config
			if path == "" {
				p, err := config.Path()
				if err != nil {
					return err
				}
				path = p
			}
			switch {
			case pathOnly:
				sayln(a.out, path)
				return nil
			case initFile:
				return writeTemplate(a, path, force)
			}
			if err := a.ensureConfig(); err != nil {
				return err
			}
			cfg, used, err := config.Load(a.flags.config)
			if err != nil {
				return err
			}
			say(a.out, "# %s\n", used)
			b, err := yaml.Marshal(cfg)
			if err != nil {
				return err
			}
			_, err = a.out.Write(b)
			return err
		},
	}
	fl := c.Flags()
	fl.BoolVarP(&initFile, "init", "i", false, "write the commented default config file")
	fl.BoolVarP(&force, "force", "f", false, "with --init, overwrite an existing file")
	fl.BoolVarP(&pathOnly, "path", "p", false, "print the config file path only")
	return c
}

func writeTemplate(a *app, path string, force bool) error {
	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("%s already exists (use --force to overwrite)", path)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := config.WriteTemplate(path); err != nil {
		return err
	}
	sayln(a.out, "wrote "+path)
	return nil
}
