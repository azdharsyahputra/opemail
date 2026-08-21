package cli

import (
	"fmt"

	"github.com/azdharsyahputra/openmail/internal/storage"
	"github.com/spf13/cobra"
)

var gcDryRun bool

var storageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Manage storage and blob store",
}

var storageGCCmd = &cobra.Command{
	Use:   "gc",
	Short: "Garbage collect orphaned blobs from storage",
	RunE: func(cmd *cobra.Command, args []string) error {
		stats, err := storage.GarbageCollect(cmd.Context(), blobStore, messageRepo, gcDryRun)
		if err != nil {
			return fmt.Errorf("garbage collection failed: %w", err)
		}

		fmt.Println("Garbage Collection Complete")
		fmt.Printf("Total Blobs in Storage:  %d\n", stats.TotalBlobs)
		fmt.Printf("Referenced in Database:  %d\n", stats.ReferencedBlobs)
		fmt.Printf("Orphaned Blobs Detected: %d\n", stats.OrphanBlobs)
		if gcDryRun {
			fmt.Println("Mode: DRY RUN (No files were deleted)")
		} else {
			fmt.Printf("Orphaned Blobs Deleted:  %d\n", stats.DeletedBlobs)
		}

		return nil
	},
}

func init() {
	storageGCCmd.Flags().BoolVar(&gcDryRun, "dry-run", false, "Simulate GC without deleting any files")
	storageCmd.AddCommand(storageGCCmd)
}
