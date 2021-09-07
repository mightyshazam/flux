// Code generated by vfsgen; DO NOT EDIT.

package install

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	pathpkg "path"
	"time"
)

// templates statically implements the virtual filesystem provided to vfsgen.
var templates = func() http.FileSystem {
	fs := vfsgen۰FS{
		"/": &vfsgen۰DirInfo{
			name:    "/",
			modTime: time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		"/flux-account.yaml.tmpl": &vfsgen۰CompressedFileInfo{
			name:             "flux-account.yaml.tmpl",
			modTime:          time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
			uncompressedSize: 826,

			compressedContent: []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xa4\x52\xbb\x8e\xdb\x30\x10\xec\xf9\x15\x03\xb8\x70\x12\x58\x0a\xd2\x05\xea\x6c\x17\x29\x12\xa4\x50\x1e\x4d\x90\x62\x45\xae\xce\x3c\xd3\xa4\xc0\x87\xef\x21\xe8\xdf\x0f\x92\x7c\x07\xcb\xf6\x1d\x60\x5c\xc7\xdd\x9d\xe5\xce\xce\x4e\x96\x65\x62\x86\xdf\x1b\x46\x60\xbf\xd7\x92\x41\x52\xba\x64\xe3\x02\xd2\xa4\x10\xd9\xc3\x3b\xc3\x61\x01\xb2\x6a\x92\x42\xa5\xad\xd2\xf6\x06\xe4\x59\xcc\xe0\xac\x79\x80\x65\x56\xac\x50\x3b\x8f\xef\xa9\x62\x6f\x39\x72\xc0\x9d\x8e\x9b\xa1\x25\xab\x28\xb0\xea\x27\x70\x08\x90\xce\x46\xef\x0c\x3e\x94\xab\xe5\xfa\x63\x2e\xa8\xd1\x7f\xd9\x07\xed\x6c\x81\xfd\x17\xb1\xd5\x56\x15\xf8\x35\xb2\x5a\x8e\xa4\xc4\x8e\x23\x29\x8a\x54\x08\xc0\x50\xc5\x26\xf4\x2f\xc0\xd2\x8e\x0b\xd4\x26\xdd\x8b\xe3\xa0\x6d\xa1\x6b\xe4\x3f\x69\xc7\xa1\x21\xc9\xe8\xba\x43\x7d\x08\x0b\xb4\xed\xb4\xda\xb6\x60\xab\xba\x4e\xf4\xba\x1c\x13\xf2\x15\xc9\x9c\x52\xdc\x38\xaf\x1f\x29\x6a\x67\xf3\xed\xd7\x90\x6b\xf7\xf9\x85\xea\x7a\x14\xa7\x74\x86\xaf\xe5\x29\x7c\x32\x3c\x40\x32\x50\xa3\xbf\x79\x97\x9a\x50\xe0\xdf\xfc\xd3\xfc\xff\xd0\xe7\x39\xb8\xe4\x25\x4f\x92\x7b\xf6\xd5\x51\x22\x83\x75\xb6\x3c\x00\xff\x94\x3f\x5e\xc7\xbe\x6f\xb9\xd5\x78\xf7\xeb\x77\x74\x86\x4b\xae\x7b\xd0\xf3\x8e\x6f\x8c\x16\xc0\xb9\xac\x93\xff\x42\xaa\x6e\x59\xc6\x83\x6c\x17\xed\x72\x46\xe7\xf4\xf8\xa7\xee\xb8\xe4\x07\x13\xfa\x97\xe2\x9a\x92\x89\xa3\x41\x7a\x1f\x3d\x05\x00\x00\xff\xff\xdb\x2d\xc3\x7c\x3a\x03\x00\x00"),
		},
		"/flux-deployment.yaml.tmpl": &vfsgen۰CompressedFileInfo{
			name:             "flux-deployment.yaml.tmpl",
			modTime:          time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
			uncompressedSize: 7263,

			compressedContent: []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xd4\x59\xdd\x6f\x1b\x37\x12\x7f\xf7\x5f\x31\x50\x0e\x48\x0c\x48\x2b\xbb\x6e\x8b\xc3\xf6\x5c\x5c\x9a\x0f\x37\x97\x26\x35\xec\xe4\x0e\x7d\xaa\x29\xee\x48\x4b\x88\x4b\xee\x71\xb8\x52\x17\x46\xff\xf7\xc3\x90\xfb\xc1\x95\x65\xa7\xc8\xdb\xf9\x21\xb1\xc9\xe1\x70\xe6\x37\xdf\xdc\xc5\x62\x71\x22\x6a\xf5\x6f\x74\xa4\xac\xc9\x41\xd4\x35\x2d\x77\xe7\x27\x5b\x65\x8a\x1c\x5e\x63\xad\x6d\x5b\xa1\xf1\x27\x15\x7a\x51\x08\x2f\xf2\x13\x00\x23\x2a\xcc\x61\xad\x9b\x3f\xee\xef\x41\xad\x21\xfb\x28\x2a\xa4\x5a\x48\x84\x3f\xff\xec\xf6\xc3\x9f\x39\xdc\xdf\x4f\x77\xef\xef\x01\x4d\xc1\x64\x54\xa3\x64\x66\x0e\x6b\xad\xa4\xa0\x1c\xce\x4f\x00\x08\x35\x4a\x6f\x1d\xef\x00\x54\xc2\xcb\xf2\x17\xb1\x42\x4d\x71\x21\xbd\x9b\xa9\xbd\x13\x1e\x37\x6d\xdc\xf4\x6d\x8d\x39\xdc\xa0\x74\x28\x3c\x9e\x00\x78\xac\x6a\x2d\x3c\x76\xcc\x12\x0d\xf8\x47\x18\x63\xbd\xf0\xca\x9a\x81\x39\x40\xed\x6c\x85\xbe\xc4\x86\x32\x65\x97\xb5\x75\x3e\x87\xd9\xc5\xd9\xc5\xf9\x0c\x9e\x81\x47\xad\x13\x0a\xf0\x16\x48\x3a\x51\x23\x2c\x2b\xf4\x4e\x49\x62\xe5\x6a\xab\x8c\x7f\x4e\xc0\x87\xb3\x8e\xb1\x9e\xe8\x70\xa0\x05\x40\x8f\x45\xd8\xb2\x05\xde\x4e\x50\xe0\x9f\x15\x7a\x91\x6d\x9b\x15\x3a\x83\x1e\x83\x70\x96\x72\xd0\xca\x74\x2c\x18\x3a\xb7\x53\x12\x5f\x4a\x69\x1b\xe3\x3f\x4e\x6f\x00\xd8\x59\xdd\x54\x38\xc8\xb0\xe8\x64\xd8\x28\xbf\xd8\x62\x3b\x5c\x44\x0c\x9f\x1f\x2f\xee\x57\x46\x7e\x0b\x3e\x52\x04\xcf\x48\xa8\x0a\x5c\x8b\x46\xfb\x0f\xb6\xc0\x1c\xce\xbe\x3d\x3b\x83\x67\xb0\x2f\xd1\x40\xc5\xd2\x60\x01\x0e\x45\xb1\xb0\x46\xb7\x73\xd8\x23\xec\xad\x79\xee\x61\x85\x20\x56\x1a\x19\x48\x59\x56\xb6\x38\xe9\x18\x3e\x83\x4f\xa5\x22\x50\x04\x02\x7c\x55\xaf\x09\x1a\xc2\x02\xd6\xd6\xc1\x06\x0d\x3a\xe1\x95\xd9\xc0\xed\xed\xcf\xb0\xc5\x96\x32\x78\x67\xe0\xfd\xdf\x09\x7e\xbc\x84\xf3\xec\xfc\x6c\x3e\x70\xe9\xef\x8e\x2a\x10\x08\x87\xa9\x1c\x64\x59\x14\x83\x58\x80\x00\xc2\x5a\xb0\x37\x75\x40\xc1\x1e\x07\x36\x52\x18\xd8\x3b\xe5\x59\xd0\xec\x38\x7e\x1b\x34\x03\x18\x58\xd5\xbe\x7d\xad\x5c\x0a\x62\x85\x85\x6a\xaa\x1c\x3e\x60\x65\x5d\x9b\xea\x89\xb0\xb6\x5a\xdb\x3d\x6b\xd4\x5d\xad\x28\xa8\xda\x10\xaf\x09\x90\x0d\x79\x5b\x29\x46\x60\x6b\xec\xde\xfc\x5e\x5a\xf2\x34\xb0\x58\x2b\x8d\x73\xd8\x97\x4a\x96\xd0\xda\x06\xf6\x4a\xeb\xa8\x94\xb7\x50\x58\x0e\x50\x5e\xe6\x43\xfc\x8b\x03\xbb\x37\x2c\xf6\xc0\xc0\x61\x6d\xc1\x09\x5f\xa2\x03\x5f\x0a\xd3\x5d\xbc\x51\xbe\x6c\x56\x60\x79\x11\x41\xab\x2d\x66\xf0\x9b\x6d\x9e\x6b\x0d\x42\x93\xed\xaf\x98\x82\x0d\xca\x83\x32\xde\x86\x33\xd2\x1a\x2f\x94\x41\x37\x87\x15\x6a\xbb\xcf\xe0\x16\x47\x54\x4b\xef\x6b\xca\x97\x4b\xf6\x29\x59\xb0\x47\x6b\xdc\x08\xd9\x86\x85\xe5\xa6\x51\x05\xd2\xb2\x21\x5c\xd4\x4e\xed\x84\xc7\xe0\x77\xac\xc5\x72\x60\xd1\x1b\x81\xa8\x5c\x48\x6b\xd6\x6a\x33\x6c\x01\xc4\x85\x0f\xa2\xce\x93\xc5\x34\xf4\x16\xc9\xb1\xaf\x35\x48\x88\xc9\x65\x64\x32\xfa\xdd\x17\x8d\xb1\x57\x54\xf2\x4a\x29\x76\x08\x02\x0a\xb5\x5e\xa3\xe3\x34\xdb\x73\xe8\xc2\x69\x4c\xa5\x01\xfb\xc8\x2e\x45\x9f\xd3\xd1\x4e\x15\xd8\xe3\xbd\x56\x9b\x4a\xd4\xa3\x20\xca\x97\x20\x0c\xa0\xf1\xae\x0d\x3a\xdc\x45\xa2\xbb\x39\x08\x53\x40\x63\xa4\xad\x38\xbf\x87\xf3\x51\xdb\x0f\xc1\x8e\xc2\x14\x03\x17\x34\xbb\xc0\x41\x21\x75\x86\x7c\x60\x01\x86\xe1\x2b\x2c\x90\x1c\xfb\xa2\x05\x42\x0a\xf0\x16\x54\xc5\x99\x15\xae\xae\xaf\x42\xf4\xc3\x0b\x56\x8b\xd4\xc6\x28\x33\x5e\xce\xca\xed\xd0\xa9\xb5\x92\x21\xc5\x43\xdd\xb8\xda\x12\xd2\xe9\x5f\x00\x72\xe0\x12\xf3\x46\x44\x91\x01\xe2\xfb\xfe\x02\x70\x20\xdc\x66\x8c\xcf\x47\x10\xdb\xd4\x1b\x4e\x1c\x94\x40\x33\xcd\xbd\xcf\x1e\xc9\xbe\x0f\xcf\x1d\xc9\xbe\x3d\x9c\x43\x08\x3e\x48\xfc\x49\x69\xe8\x50\x77\x18\x12\xa4\xb1\x30\xcb\xb9\x6c\x92\x9f\x81\xaa\xc4\x06\xa3\xf7\xf3\x81\x0c\xde\x2a\x53\x04\x9d\x2b\xce\x27\x0e\xe5\xe8\xb5\x31\x97\x68\x14\x84\x9c\x35\xc2\x51\x36\x02\x77\x16\x20\xfc\x10\xf0\x65\xb3\xca\x0a\x2b\xb7\xe8\x32\x69\xab\xa5\xeb\x32\x40\x8c\x7b\x2f\x06\xe8\x7a\x3b\x72\x87\xc0\xdd\x03\xdf\xea\xc5\x06\x58\xd2\x6c\xa0\x09\xd7\xe4\xd0\x31\x54\x36\xe5\x96\x9f\x67\xdf\x7c\x9b\x9d\x4d\x69\xaf\x1b\xad\xaf\xad\x56\xb2\xcd\xe1\xdd\xfa\xa3\xf5\xd7\x0e\x29\xd5\xc2\x21\xd9\xc6\x49\xa4\x34\x81\x3b\xfc\x6f\x83\xe4\x27\x6b\x00\xb2\x6e\x72\xf8\xee\xac\x9a\x2c\x56\x21\xc7\xe7\xf0\xfd\xb7\x1f\xd4\xd8\x58\x58\x97\x1e\x5e\x8c\x96\xb9\x0e\x4d\xc6\xc5\xd9\x05\x97\x4c\x65\xd6\xd6\x55\xc1\x65\x85\x1e\xa8\xb5\xda\xa1\x41\xa2\x6b\x67\x57\x98\x4a\xc0\x90\x5e\x4d\xcb\x75\xbc\x2a\x32\x9c\x2e\x0b\x5f\xe6\xb0\x14\xb5\x8a\x48\xef\xbe\x5f\xaa\x02\x8d\x57\xbe\xcd\xea\x66\x95\xd0\x2a\xa3\xbc\x12\xfa\x35\x6a\xd1\xde\x72\x7c\x16\x94\xc3\x77\x09\x81\x57\x15\xda\xc6\x1f\xd9\xe3\xea\xaa\xfe\x3f\x44\x4d\x82\x76\x62\x98\xe3\x7d\x11\xc4\xfa\x76\x1d\x25\x43\x2f\x83\x64\xc5\x92\xa8\xe4\xce\xd0\xc6\x5e\x15\xb4\xed\xf2\xcd\x86\x4d\x06\xca\x44\x9f\x7b\x4e\xf1\x0c\x51\xb9\x9c\xa4\xc9\x1e\xb3\x5f\x8d\x6e\x73\xf0\xae\x41\xe6\xc6\xcd\x4f\xc8\x50\xab\x2e\xb1\x73\x48\xd5\xe8\xd6\xd6\x49\x64\xa6\xb1\xdb\xe1\x66\xe7\x31\xc1\xd3\x86\x64\x2a\xfb\x4e\xb8\x4e\xf6\x48\xf6\x75\xe2\x27\x31\xfa\xce\x48\xdd\x84\xcc\xc9\x3d\x5b\x2c\x70\x7d\x56\x8d\x4d\xc1\x17\x7a\x98\xbe\x8b\xf9\x81\x8f\x1e\xf4\x17\x43\x76\x85\x02\xa5\x16\x8e\x7b\xb5\x95\xdd\x25\x09\xe0\x89\x36\x20\xa6\xc7\x54\x79\x67\xad\x5f\x66\x44\xe5\xa3\x0a\x08\x33\xb9\x75\x36\x96\xa8\x59\xbc\x79\xde\x93\x24\x1c\xd0\xec\x94\xb3\x26\x14\x84\x58\x6b\x67\xef\x3f\xff\xf4\xe6\xd5\xaf\x1f\xdf\xbe\xbb\x9a\xc5\x12\x30\x67\x3c\xec\x0e\x9d\x9b\xd6\xeb\x84\x4d\x28\x71\xab\x36\x56\x53\xaf\x8f\xe9\xf8\xa0\xd0\x3e\xd4\x71\x74\x4e\x26\x7e\x54\x51\xae\x79\x3c\xaa\xf4\xb7\x71\x8a\x4e\x5a\x91\x4e\xba\x60\x93\x84\xc5\x61\x43\x93\x1a\x3d\x74\x33\x7d\xcf\x2d\x0c\x08\xed\xd1\x19\xee\xa9\x1f\x48\xbc\x76\xb6\x62\xb7\xe8\x3b\x96\x39\x08\x62\x77\xeb\xaa\x2a\xc3\xa0\xad\xdc\xd2\x43\x63\xa3\xd9\xe5\x47\x70\x19\xe1\x9e\xe0\xb2\x13\xba\xc1\x07\x98\x7c\xc9\x89\x0f\x7d\xa0\xaf\xb9\x4f\x78\x00\x97\xfc\x69\xa9\x7f\xa2\xd8\x3f\xe2\x97\x4c\x15\xbb\x9b\x09\xdd\x34\x3f\x7c\x29\xf2\xf6\x82\x9b\x12\x0b\xd4\xd4\xb5\x6e\xe1\xe7\x4f\x9f\xae\x61\x25\x48\x49\x10\x8d\x2f\x41\x3a\x0c\x99\x54\xe8\x58\xd5\xc7\x41\x80\x19\xee\x94\x08\x8a\xdf\x5d\xbd\xfb\xf4\xfb\xcb\xcf\x9f\x7e\xfe\x7c\xfb\xe6\xe6\x2e\xa8\x3b\x2c\xbd\x7f\xf3\xdb\xdd\xc4\xe1\x77\xc2\x29\x1e\xe3\xa8\x6f\x90\x13\x86\xb1\x7d\x39\xb0\xdf\x5b\x67\xab\xa9\x0d\x23\xd9\x0d\xae\xf3\x89\xe6\x93\x5e\x91\x13\x1b\xab\x30\x02\xc0\x98\xe7\x13\x3c\x22\x04\x71\x38\xc5\x82\x2b\xb1\x14\xb2\xc4\x82\x5d\x2b\xf5\xed\xa1\xad\x66\xa4\x98\xfb\x3c\xe1\x62\x5d\xd7\x37\x27\x07\xba\xe1\x3a\x1c\x9c\x87\x4b\x78\x28\xec\x30\xf6\x25\x52\xea\x0b\x63\xf7\xea\xf7\x96\xa5\x6c\x18\xa7\x10\x71\xe1\x09\x21\x38\x22\x94\x76\x1f\x06\x5f\x6b\x0c\xca\x60\x32\xe5\xa7\xbe\xb3\x58\x0c\x0a\x84\xc1\x87\x2f\xbf\x1c\x96\xb2\xae\xe9\xcb\x68\x27\x33\xa9\x1b\xf2\xe8\x32\x4e\xe0\x3a\x85\xe4\x33\xc5\x5c\x33\x42\xf1\x2a\x92\xbe\xbb\x9e\x28\xc5\x69\x87\xd0\x87\xc1\x7a\xea\xd9\xa3\x0c\x3d\x3d\x7b\x97\x77\x4c\x19\x46\xdd\xa4\x04\xa5\x12\x77\xd4\x97\x27\x93\x2e\x53\x11\x54\x0d\x85\xd1\x3f\xa0\xa7\xb0\x88\xe1\xb4\x0a\x85\x2d\xf4\x78\x61\xe2\x7f\xd1\x8f\xd1\xa7\xa9\x2c\x7d\x72\x89\x61\xc8\x0e\x9c\x0c\xfe\x13\x41\xb8\x18\xc4\x02\xb7\x28\x94\xbb\x7c\x50\xf6\x52\xb1\x6e\x92\x0e\x73\x34\xde\xe7\x9b\x5f\xe2\xcb\x84\x30\x9b\xb8\x77\xa5\x7c\x98\x96\x49\x79\xeb\xda\x21\x5d\xbf\xe5\xce\x38\x61\xf7\x54\xcc\xb1\xdb\x24\xba\x77\x21\x73\x34\x9c\xd2\x58\xe8\x7b\xe7\xbf\xbd\x48\x23\xf3\x34\x1f\xff\x7e\xff\xe6\xb7\xd3\x7f\xc6\x99\x3d\xb4\xd5\x0d\xa1\x5b\x8e\xc2\x66\x69\xa0\x33\x3e\x1c\x4e\x8d\xd3\x97\xf7\xf7\x90\x5d\x29\xcf\xca\x86\xc7\xbb\x29\xc5\xca\x09\x23\xcb\x9e\xe8\xa7\xf0\x57\x7c\xc6\x53\xeb\xb0\xc4\xf9\x8b\x8e\x9d\xe4\x1e\x8e\xcf\xdd\x06\x4f\xa1\x7f\x59\x65\x92\x03\xb3\xf9\xac\x7b\x0d\xd4\x84\xe9\xf1\xa7\x93\x9a\x43\x76\x3c\x19\xa7\xae\x4a\x18\xb5\xe6\x9e\x9c\x63\x88\x54\x81\x2e\x9a\xe3\x60\xb2\x09\x8f\x11\x96\x10\x1a\x53\xa0\x3b\xb0\xb1\x43\x2d\xbc\xda\x61\x68\x39\xa9\xf7\xc0\xcd\xc4\xce\x07\x31\x39\x28\x47\xcd\xaa\x50\xee\x7c\x1e\xff\xff\x66\x78\xda\x1c\xc1\x09\x4f\x97\xc7\xc0\x09\xef\x81\x3d\xaa\x3d\xd5\x11\x06\x9f\x09\xdd\xb1\xf3\x6c\xdc\xc1\x72\x4c\x03\xc7\xcf\xbf\xa9\x84\x3a\x2a\x00\xf2\x46\xcf\xa1\xa7\x1a\x1f\x67\x8f\x9a\x03\x39\x95\xec\x2d\x03\x8a\x26\xbc\xdb\x31\x4e\x5c\xb1\x95\x3f\x18\xc0\x53\xac\xba\xda\xd7\x55\xb6\xcb\x27\x4a\x5d\x7f\xa2\xe3\xc5\xa7\x2e\xff\xb1\xc5\x16\x54\xf1\xe3\x40\xf6\x44\x3b\x93\x48\xc5\x2c\x84\x6f\x1c\x4e\x5e\x01\x8e\xdc\x15\xb6\xdb\xc5\x40\x4f\x93\x74\xd5\x67\x6b\x50\x1e\x4a\x41\xa1\x14\x5b\xa3\x5b\x10\x52\x22\xc5\x8c\x5e\x62\x7c\x41\x7b\xd1\xbf\xd9\xdc\xad\x85\x26\xbc\x3b\x3d\xb9\xbf\x5f\xf4\x86\xb8\xe9\x6a\xf8\x31\x5b\xf4\x4c\x03\xfd\xc3\x78\x38\x4e\x76\xc4\x4e\xe4\x5d\x23\x7d\x94\x77\x1f\xc6\x79\x6e\xf1\x1a\x0f\xd4\x1a\x09\x2b\x6b\xb7\x5b\xc4\x9a\xbd\x7e\x10\x75\xb6\x51\x7e\x36\x87\x0a\x05\x03\xce\x09\x0d\x44\x98\xb1\xbb\x40\x68\x6a\xf2\x0e\x45\x35\x44\xc4\xe9\x81\x60\xcc\x7a\x41\x5e\x78\xbc\xe4\x04\xf3\xa8\xdf\x18\xfc\xc3\xf7\xce\x93\x54\x3c\x61\x60\xd6\xdf\x31\xeb\xeb\x51\xc2\xe4\x05\x66\x9b\x6c\x0e\xff\x41\xee\x2c\x5f\x69\xdb\x14\xa7\x59\x78\x20\xf2\x76\xcb\xf3\x09\x41\x2d\x9c\x57\xb2\xd1\xc2\xf5\xc6\xe8\xb8\x1c\x96\xd2\xee\xd6\xcb\x3d\x71\x1e\x95\xcc\x2b\xdb\x33\xdf\x6c\x6f\xdd\x96\x86\x61\xf3\xe0\x58\xb8\xe8\x52\xac\xe4\xf9\x37\x17\x0f\xff\x4d\x15\x7e\x13\xbd\xaf\xcf\x4a\xc3\x4b\xb5\x35\x4f\xb8\xc6\x87\x8e\xfa\x6a\x24\x3e\xf0\x90\x9e\xdf\x62\xe4\x77\x19\xfa\xc0\xc7\xbd\xe5\xd8\x91\x70\xf1\x23\xae\x73\x8b\x6e\x77\xe4\x1b\x06\x0f\x04\x63\x07\xc4\xb1\xfa\x43\x5a\x8a\xc5\x96\xcb\x58\xf4\x32\x42\x9f\x7c\x18\x79\x9e\x7c\x5b\x49\x3e\x92\xb0\x71\xc2\xd3\x5d\x68\xca\xb3\x89\x96\x5a\x91\x47\xb3\xe8\x44\xb8\xcc\x2f\xce\x2e\xce\x07\x90\x6e\x70\xa3\xc8\xbb\xf6\xb5\x22\x86\xf8\x56\x0a\x13\xdc\xf5\x00\x29\xd7\x91\x2d\x8a\x48\xb7\xa0\x8e\x30\x55\xbb\xcb\x8d\x2f\x8b\x42\xc5\x47\x16\x2e\xde\x2f\xb9\x79\x9f\xc0\x38\xee\x8f\xfd\xdb\xfd\x3d\xb8\xd0\x0a\x7c\xe1\xf4\x22\x7c\xf5\x9a\xe4\xd3\xf1\xb7\xfe\x82\x5f\xeb\x8e\xfd\xeb\x8f\xb7\x7d\xe3\x45\xf3\x6e\x20\x6a\x5c\xd7\x86\x81\x29\xac\x27\xb0\x81\x18\x2a\xd1\x86\xc7\x29\xbd\x1b\x9f\x28\x0d\x69\x6b\xb7\x4d\x0d\x8a\xa8\x41\x02\x6b\x80\x6c\x85\xf0\x7e\xf8\x56\xc4\xdc\x9b\x9a\xc6\x17\xc8\xc2\x50\xff\xfe\x35\xfb\x68\x0d\xce\xd2\x9d\x57\x41\x80\xf4\x0d\x32\x5e\x4e\xd3\x67\xc9\x7e\xb0\x09\xf2\x4d\x76\x86\x99\x6b\x76\x3e\x3b\xf9\x5f\x00\x00\x00\xff\xff\x22\x3f\xca\x04\x5f\x1c\x00\x00"),
		},
		"/flux-secret.yaml.tmpl": &vfsgen۰CompressedFileInfo{
			name:             "flux-secret.yaml.tmpl",
			modTime:          time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
			uncompressedSize: 137,

			compressedContent: []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\x54\xca\x31\x0a\xc2\x40\x10\x85\xe1\x7e\x4f\xf1\x2e\xb0\x82\xed\x1c\x42\x0b\xc1\x7e\xc8\xbe\xc8\x62\xb2\x19\x93\x89\x18\x86\xdc\x5d\x14\x1b\xcb\x9f\xff\xcb\x39\x27\xb5\x7a\xe5\xbc\xd4\xa9\x09\x9e\xc7\x74\xaf\xad\x08\x2e\xec\x66\x7a\x1a\xe9\x5a\xd4\x55\x12\xd0\x74\xa4\xa0\x1f\xd6\x57\xbe\x55\xcf\x85\x36\x4c\x5b\x04\x6a\x8f\xc3\x49\x47\x2e\xa6\x1d\xb1\xef\x3f\xfa\x4d\x41\xc4\xff\x8d\x00\x5b\xf9\x30\xdf\x8c\x82\xb3\xe9\x63\x65\x7a\x07\x00\x00\xff\xff\x40\x21\xa1\xbb\x89\x00\x00\x00"),
		},
		"/memcache-dep.yaml.tmpl": &vfsgen۰CompressedFileInfo{
			name:             "memcache-dep.yaml.tmpl",
			modTime:          time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
			uncompressedSize: 974,

			compressedContent: []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\x6c\x53\xcd\x6e\xdb\x3c\x10\xbc\xeb\x29\x06\xf0\xf5\x93\xf2\x29\x40\x7a\xd0\x2d\x68\xda\x22\x40\x1b\x18\x08\xd2\xfb\x9a\x5a\x29\x44\xf8\x57\x72\xe9\x5a\x15\xf2\xee\x85\x64\xc7\x96\x9a\xec\x49\xe2\xcc\xce\xce\x72\x97\x65\x59\x16\x1b\x58\xb6\x8a\xd4\x33\xb7\x68\x39\x18\x3f\x58\x76\x82\x9c\xb8\xc5\x6e\xc0\x57\x93\x0f\x10\x8f\x99\x51\x6c\xa0\xbc\x13\xd2\x8e\x23\xb4\xa5\x9e\x61\x59\xa8\x25\xa1\xaa\xa0\xa0\x7f\x72\x4c\xda\xbb\x06\x14\x42\xba\xda\xd7\xc5\x8b\x76\x6d\x83\xbb\xb3\x6c\xf1\x46\x6f\x0a\xc0\x91\xe5\xe6\x52\x7d\x1c\xa1\x3b\x54\x0f\x64\x39\x05\x52\x8c\xd7\xd7\x13\x69\xfe\x6d\x30\x8e\x6b\x74\x1c\xc1\xae\x9d\x68\x29\xb0\x9a\x14\x23\x07\xa3\x15\xa5\x06\x75\x01\x24\x36\xac\xc4\xc7\x09\x01\x2c\x89\x7a\xfe\x4e\x3b\x36\xe9\x78\xf0\xce\x40\x01\x08\xdb\x60\x48\xf8\x94\xb2\x30\x3b\x85\x59\x65\x7f\x94\x0f\xbc\x59\x99\x71\xdf\xf2\xe3\xca\xc4\x14\x3b\x16\xaa\x5e\xf2\x8e\xa3\x63\xe1\x54\x69\x7f\xe5\x53\x03\xa3\x5d\x3e\x9c\x48\xe7\x4b\x3e\x17\x2b\x3f\x2c\x36\xc5\x3c\x86\x05\xd0\xd4\xd5\xa7\xaa\xfe\xbf\x24\x13\xb4\xe3\x35\x6d\x9b\x8d\xd9\x7a\xa3\xd5\xd0\xe0\xbe\x7b\xf0\xb2\x8d\x9c\xa6\xb1\xbc\xb1\x28\xf6\x8b\xfe\x4a\x94\x16\x37\xf5\x35\x80\x0d\x7e\xd0\x41\xdb\x6c\xa7\x42\x3e\x0e\xd3\x4a\xe4\xc4\xff\x41\x3b\x58\xee\x69\x37\x08\xa7\x65\xe2\x3d\x6e\x2c\x56\x89\x49\xff\x61\x74\x3e\xc2\x3b\x86\x16\xb6\x4b\x7a\x40\x5d\x5f\xd7\x35\x36\xb8\xe3\x8e\xb2\x11\x04\x1f\x2f\xbe\x36\x13\x67\xbf\x3f\x7e\x3e\x39\xe5\xed\xbc\xa4\xe2\xd1\xb3\xc0\xf8\x3e\xc1\x77\x60\x52\xcf\x88\xfc\x2b\x73\x12\x90\x6b\x11\x39\x05\xef\x12\x57\x67\xa1\x49\x75\xd5\xe1\xf1\x5a\x95\xd1\xec\xe4\xd2\xc0\x62\x04\x5b\x1f\xa5\x39\xba\x3b\x6d\xe8\x6d\xdb\x3e\xb2\xca\x51\xcb\xf0\xd9\x3b\xe1\x83\xcc\x9b\x7a\x8c\xb4\x46\x9a\x85\x64\xcc\xee\x36\x3d\x25\x8e\x27\xb9\x7f\xa1\x6f\xd1\xe7\xf0\x1e\x23\x63\xfc\xef\x6d\xd4\x7b\x6d\xb8\xe7\x2f\x49\x91\x21\x99\x5f\x59\x47\x26\xf1\xe5\x15\xfc\x0d\x00\x00\xff\xff\x3f\x87\x20\x76\xce\x03\x00\x00"),
		},
		"/memcache-svc.yaml.tmpl": &vfsgen۰CompressedFileInfo{
			name:             "memcache-svc.yaml.tmpl",
			modTime:          time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
			uncompressedSize: 206,

			compressedContent: []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\x5c\x8c\x3d\x0e\x02\x21\x10\x46\x7b\x4e\xf1\x5d\x00\x13\x2c\x39\x84\x8d\x89\xfd\x04\x3e\x23\x51\x58\x02\x64\x9b\xc9\xde\xdd\xb0\x6b\xe3\x76\xf3\xf3\xde\xb3\xd6\x1a\xa9\xe9\xc1\xd6\xd3\x52\x3c\x56\x67\xde\xa9\x44\x8f\x3b\xdb\x9a\x02\x4d\xe6\x90\x28\x43\xbc\x01\x8a\x64\x7a\x64\xe6\x20\xe1\xc5\xa8\x8a\xf4\xc4\xe5\x26\x99\xbd\x4a\x20\xb6\xed\x07\xed\xab\x87\xea\xff\x57\x15\x2c\x71\x62\xbd\x32\xcc\x62\x5d\xda\xe8\x73\x00\xec\x39\xbf\x5f\x0f\xc4\xc3\xb9\xab\x73\x06\xe8\xfc\x30\x8c\xa5\x1d\xce\xd9\xf8\x06\x00\x00\xff\xff\x20\x2f\xef\xba\xce\x00\x00\x00"),
		},
	}
	fs["/"].(*vfsgen۰DirInfo).entries = []os.FileInfo{
		fs["/flux-account.yaml.tmpl"].(os.FileInfo),
		fs["/flux-deployment.yaml.tmpl"].(os.FileInfo),
		fs["/flux-secret.yaml.tmpl"].(os.FileInfo),
		fs["/memcache-dep.yaml.tmpl"].(os.FileInfo),
		fs["/memcache-svc.yaml.tmpl"].(os.FileInfo),
	}

	return fs
}()

type vfsgen۰FS map[string]interface{}

func (fs vfsgen۰FS) Open(path string) (http.File, error) {
	path = pathpkg.Clean("/" + path)
	f, ok := fs[path]
	if !ok {
		return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrNotExist}
	}

	switch f := f.(type) {
	case *vfsgen۰CompressedFileInfo:
		gr, err := gzip.NewReader(bytes.NewReader(f.compressedContent))
		if err != nil {
			// This should never happen because we generate the gzip bytes such that they are always valid.
			panic("unexpected error reading own gzip compressed bytes: " + err.Error())
		}
		return &vfsgen۰CompressedFile{
			vfsgen۰CompressedFileInfo: f,
			gr:                        gr,
		}, nil
	case *vfsgen۰DirInfo:
		return &vfsgen۰Dir{
			vfsgen۰DirInfo: f,
		}, nil
	default:
		// This should never happen because we generate only the above types.
		panic(fmt.Sprintf("unexpected type %T", f))
	}
}

// vfsgen۰CompressedFileInfo is a static definition of a gzip compressed file.
type vfsgen۰CompressedFileInfo struct {
	name              string
	modTime           time.Time
	compressedContent []byte
	uncompressedSize  int64
}

func (f *vfsgen۰CompressedFileInfo) Readdir(count int) ([]os.FileInfo, error) {
	return nil, fmt.Errorf("cannot Readdir from file %s", f.name)
}
func (f *vfsgen۰CompressedFileInfo) Stat() (os.FileInfo, error) { return f, nil }

func (f *vfsgen۰CompressedFileInfo) GzipBytes() []byte {
	return f.compressedContent
}

func (f *vfsgen۰CompressedFileInfo) Name() string       { return f.name }
func (f *vfsgen۰CompressedFileInfo) Size() int64        { return f.uncompressedSize }
func (f *vfsgen۰CompressedFileInfo) Mode() os.FileMode  { return 0444 }
func (f *vfsgen۰CompressedFileInfo) ModTime() time.Time { return f.modTime }
func (f *vfsgen۰CompressedFileInfo) IsDir() bool        { return false }
func (f *vfsgen۰CompressedFileInfo) Sys() interface{}   { return nil }

// vfsgen۰CompressedFile is an opened compressedFile instance.
type vfsgen۰CompressedFile struct {
	*vfsgen۰CompressedFileInfo
	gr      *gzip.Reader
	grPos   int64 // Actual gr uncompressed position.
	seekPos int64 // Seek uncompressed position.
}

func (f *vfsgen۰CompressedFile) Read(p []byte) (n int, err error) {
	if f.grPos > f.seekPos {
		// Rewind to beginning.
		err = f.gr.Reset(bytes.NewReader(f.compressedContent))
		if err != nil {
			return 0, err
		}
		f.grPos = 0
	}
	if f.grPos < f.seekPos {
		// Fast-forward.
		_, err = io.CopyN(ioutil.Discard, f.gr, f.seekPos-f.grPos)
		if err != nil {
			return 0, err
		}
		f.grPos = f.seekPos
	}
	n, err = f.gr.Read(p)
	f.grPos += int64(n)
	f.seekPos = f.grPos
	return n, err
}
func (f *vfsgen۰CompressedFile) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		f.seekPos = 0 + offset
	case io.SeekCurrent:
		f.seekPos += offset
	case io.SeekEnd:
		f.seekPos = f.uncompressedSize + offset
	default:
		panic(fmt.Errorf("invalid whence value: %v", whence))
	}
	return f.seekPos, nil
}
func (f *vfsgen۰CompressedFile) Close() error {
	return f.gr.Close()
}

// vfsgen۰DirInfo is a static definition of a directory.
type vfsgen۰DirInfo struct {
	name    string
	modTime time.Time
	entries []os.FileInfo
}

func (d *vfsgen۰DirInfo) Read([]byte) (int, error) {
	return 0, fmt.Errorf("cannot Read from directory %s", d.name)
}
func (d *vfsgen۰DirInfo) Close() error               { return nil }
func (d *vfsgen۰DirInfo) Stat() (os.FileInfo, error) { return d, nil }

func (d *vfsgen۰DirInfo) Name() string       { return d.name }
func (d *vfsgen۰DirInfo) Size() int64        { return 0 }
func (d *vfsgen۰DirInfo) Mode() os.FileMode  { return 0755 | os.ModeDir }
func (d *vfsgen۰DirInfo) ModTime() time.Time { return d.modTime }
func (d *vfsgen۰DirInfo) IsDir() bool        { return true }
func (d *vfsgen۰DirInfo) Sys() interface{}   { return nil }

// vfsgen۰Dir is an opened dir instance.
type vfsgen۰Dir struct {
	*vfsgen۰DirInfo
	pos int // Position within entries for Seek and Readdir.
}

func (d *vfsgen۰Dir) Seek(offset int64, whence int) (int64, error) {
	if offset == 0 && whence == io.SeekStart {
		d.pos = 0
		return 0, nil
	}
	return 0, fmt.Errorf("unsupported Seek in directory %s", d.name)
}

func (d *vfsgen۰Dir) Readdir(count int) ([]os.FileInfo, error) {
	if d.pos >= len(d.entries) && count > 0 {
		return nil, io.EOF
	}
	if count <= 0 || count > len(d.entries)-d.pos {
		count = len(d.entries) - d.pos
	}
	e := d.entries[d.pos : d.pos+count]
	d.pos += count
	return e, nil
}
