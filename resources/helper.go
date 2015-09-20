package resources

//Init resources
func Init(forceFiles bool, localDir string) bool {
	// If assets not available - search for files in localdir
	assets := len(Assets.Dirs) > 0 || len(Assets.Files) > 0
	if !assets || forceFiles {
		Assets.LocalPath = localDir
		return false
	}
	return true
}
