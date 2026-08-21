package cli

import (
	"fmt"

	"github.com/azdharsyahputra/openmail/internal/database"
	"github.com/spf13/cobra"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Database migration management",
}

var migrateUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Apply all up migrations",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := database.RunMigrationsUp(db); err != nil {
			return err
		}
		fmt.Println("Migrations applied successfully")
		return nil
	},
}

var migrateDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Rollback migrations",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := database.RunMigrationsDown(db); err != nil {
			return err
		}
		fmt.Println("Migrations rolled back successfully")
		return nil
	},
}

func init() {
	migrateCmd.AddCommand(migrateUpCmd)
	migrateCmd.AddCommand(migrateDownCmd)
}
