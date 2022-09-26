package cmd

import (
	"log"

	"github.com/spf13/cobra"

	"github.com/SUNET/knubbis-fleetlock/server"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "start server",
	Long: `This starts the knubbis-fleetlock server which listens
on FleetLock requests and handles them by looking up information in a backend database.`,
	Run: func(cmd *cobra.Command, args []string) {
		configPath, err := cmd.Flags().GetString("config")
		if err != nil {
			log.Fatal(err)
		}
		server.Run(configPath)
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// serverCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	serverCmd.Flags().StringP("config", "c", "knubbis-fleetlock.toml", "The server configuration file")
}
