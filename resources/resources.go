//Dummy file overidden by go-assets-builder

package resources

import (
	"github.com/jessevdk/go-assets"
)

var Assets = assets.NewFileSystem(map[string][]string{}, map[string]*assets.File{}, "")
