package resources

import "flag"

var (
	forceFiles = flag.Bool("forceLocalFiles", false, "Force use local files instead of embedded assets")
	localPath  = flag.String("localFilesPath", ".", "Path to static and templates directory")
)

//Init resources
func Init() bool {
	// If assets not available - search for files in localdir
	assets := len(Assets.Dirs) > 0 || len(Assets.Files) > 0
	if !assets || *forceFiles {
		Assets.LocalPath = *localPath
		return false
	}
	return true
}
