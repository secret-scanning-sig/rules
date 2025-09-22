all: clean build

clean:
	git clean -dfX

build:
	./hack/$@
