VERSION=`git describe --always`
DATE=`date +%Y%m%d%H%M%S`
LDFLAGS="-X k.prv/secproxy/config.AppVersion='$(VERSION)-$(DATE)'"
GOBUILD=go

.PHONY: resources build certs

build: resources
	GOGCCFLAGS="-s -fPIC -O4 -Ofast -march=native" $(GODEP) $(GOBUILD) build -ldflags $(LDFLAGS)

build_pi: resources
	CGO_ENABLED="0" GOGCCFLAGS="-fPIC -O4 -Ofast -march=native -s" GOARCH=arm GOARM=5 go build -o  -ldflags $(LDFLAGS)
	#CGO_ENABLED="0" GOGCCFLAGS="-g -O2 -fPIC" GOARCH=arm GOARM=5 go build secproxy.go 

clean:
	go clean
	rm -fr secproxy  dist build
	find . -iname '*.orig' -delete
	git checkout resources/resources.go

run:
	# mkdir temp || true
	git checkout resources/resources.go
	go-reload secproxy.go -log.level=debug -devMode=true 
	#-log.file=secproxy.log

certs:
	mkdir -p certs
	openssl genrsa 2048 > certs/key.pem
	openssl req -new -x509 -key certs/key.pem -out certs/cert.pem -days 1000

debug: clean
	$(GOBUILD) build -gcflags "-N -l" secproxy.go
	gdb -tui ./secproxy -d $GOROOT


build_static:
	# create build dir if not exists
	if [ ! -d build ]; then mkdir -p "build"; fi
	cp -r templates build/
	if [ ! -e build/.stamp ]; then touch -t 200001010000 build/.stamp; fi
	# copy dir structure
	find static -type d -exec mkdir -p -- build/{} ';'
	# copy non-js and non-css files
	find static -type f ! -name *.js ! -name *.css -exec cp {} build/{} ';'
	# minify updated css
	find static -name *.css -newer build/.stamp -print -exec yui-compressor -v -o "./build/{}" "{}" ';' 
	# minify updated js
	find static -name *.js -newer build/.stamp -print -exec closure-compiler --language_in ECMASCRIPT5 --js_output_file "build/{}" --js "{}" ';' 
	# compress updated css
	find build -iname '*.css' -newer build/.stamp -print -exec gzip -f --best -k {} ';'
	# compress updated js
	find build -iname '*.js' -newer build/.stamp -print -exec gzip -f --best -k {} ';'
	touch build/.stamp

resources: build_static
	go-assets-builder -p=resources -o=resources/resources.go -s="/build/" build/

deps:
	#go get -d -v .
	go get -d -v ./...
	go get -v github.com/jessevdk/go-assets-builder

gofmt:
	find . -type f -name '*.go' -print -exec gofmt -s=true -w=true {} ';'
